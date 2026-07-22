// SPDX-License-Identifier: MIT OR Apache-2.0

//! Sub-flow composition (issue #92, PR 3): the built-in subflow registry, the load-time
//! validation of inline subflow definitions and subflow references, the reference cycle check,
//! and the pure [`compose`] splice that inlines every subflow into a flat journey.
//!
//! A subflow (see [`Subflow`]) is a reusable mini-journey fragment: an entry, a set of steps and
//! transitions, and one or more RETURN points (its exits). A journey declares the subflows it uses
//! in its `subflows` reference list (an alias mapped to a source) and calls one with a
//! [`StepKind::SubflowCall`] step. A reference source is either a BUILT-IN subflow this crate
//! provides (see [`builtin_subflows`]) or an INLINE definition the artifact carries in its
//! `subflow_definitions`. A subflow is a single shared definition resolved by id, so two journeys
//! that reference the same definition compile against the same fragment (edit-once-both-change);
//! version pinning is layered on in a later PR and is not built here.
//!
//! ## Purity discipline
//!
//! Every function here is PURE: it reads the artifact and returns a value or a load-time error. It
//! has NO clock, NO entropy, and NO I/O, mirroring the rest of the crate. Composition and cycle
//! detection run at LOAD, never at flow time.

use std::collections::{BTreeMap, BTreeSet};

use crate::artifact::{Journey, Predicate, Step, StepKind, Subflow, SubflowSource, Transition};
use crate::validate::{
    JourneyError, check_attachment_coherence, check_kind_and_node_group, check_predicates,
    check_reachability_and_dead_ends, check_transition_endpoints, collect_step_ids,
};

/// The name of the one required built-in subflow (issue #92, PR 3): a second-factor step up that a
/// journey can reuse without re-authoring the challenge topology.
pub const BUILTIN_MFA_STEP_UP: &str = "mfa_step_up";

/// The reserved namespace separator [`compose`] mints spliced subflow step ids with
/// (`<call_id>::<step_id>`). It is RESERVED: an author step id may not contain it (the load-time
/// validator refuses one with [`JourneyError::ReservedStepIdSeparator`]), so a hand-written id can
/// never collide with a namespaced subflow step and produce a duplicate step id after composition.
pub(crate) const NAMESPACE_SEPARATOR: &str = "::";

/// The ceiling on the number of steps a composed journey may reach (issue #92, PR 3). A journey
/// whose subflow references fan out acyclically can expand exponentially; [`compose`] refuses to
/// splice past this generous bound (far above any real journey) with
/// [`JourneyError::ComposedTooLarge`], so a pathological fan-out fails LOAD instead of exhausting
/// memory.
pub const MAX_COMPOSED_STEPS: usize = 10_000;

/// The built-in subflow registry (issue #92, PR 3): the reusable subflow fragments this crate
/// provides as pure data, keyed by their built-in name. A [`SubflowSource::Builtin`] reference
/// resolves against this map. The registry currently provides [`BUILTIN_MFA_STEP_UP`], a
/// single-step second-factor challenge whose one step is both the entry and the return exit, so a
/// journey composes it as a step-up in place and continues on return.
///
/// The map is rebuilt on each call from constant data, so a caller may freely own and mutate the
/// result; the crate never shares mutable subflow state.
#[must_use]
pub fn builtin_subflows() -> BTreeMap<String, Subflow> {
    let mut registry = BTreeMap::new();
    registry.insert(BUILTIN_MFA_STEP_UP.to_owned(), mfa_step_up());
    registry
}

/// The `mfa_step_up` built-in subflow: a single second-factor challenge step that is both the
/// entry and the return exit. On composition the calling step's return edges are grafted onto the
/// challenge step, so control steps up and then continues in the caller.
fn mfa_step_up() -> Subflow {
    Subflow {
        id: BUILTIN_MFA_STEP_UP.to_owned(),
        entry: "challenge".to_owned(),
        exits: vec!["challenge".to_owned()],
        comment: Some("Step up with a second factor, then return to the caller.".to_owned()),
        steps: vec![Step {
            id: "challenge".to_owned(),
            kind: StepKind::MfaChallenge,
            node_group: Some("totp".to_owned()),
            subflow: None,
            decision: None,
            comment: Some("Present the enrolled second factor.".to_owned()),
        }],
        transitions: vec![],
    }
}

/// Validate a journey's subflow references and inline definitions at load time (issue #92, PR 3),
/// appending every failure in deterministic document order. The checks, in order, are: duplicate or
/// name-colliding inline definition ids; each journey `subflows` reference source resolves (a
/// built-in name this crate provides, or an inline definition the artifact carries); each inline
/// definition is a well-formed fragment (validated with the same structural rules as a journey,
/// with exits playing the completion role a journey's terminals play); and no subflow references
/// itself directly or transitively. Pure and deterministic.
pub(crate) fn validate_subflows(
    doc: &Journey,
    admit_builtin_only: bool,
    errors: &mut Vec<JourneyError>,
) {
    let builtins = builtin_subflows();
    let inline = doc.subflow_definitions.as_deref().unwrap_or(&[]);

    // Duplicate inline definition ids, or an inline id that shadows a built-in name: a reference
    // could not resolve unambiguously.
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for (index, def) in inline.iter().enumerate() {
        let collides = !seen.insert(def.id.as_str()) || builtins.contains_key(def.id.as_str());
        if collides {
            errors.push(JourneyError::DuplicateSubflowDefinition {
                pointer: format!("/subflow_definitions/{index}/id"),
                id: def.id.clone(),
            });
        }
    }

    // The global definition key set a nested subflow_call resolves against: every built-in name and
    // every inline definition id.
    let mut all_keys: BTreeSet<&str> = builtins.keys().map(String::as_str).collect();
    for def in inline {
        all_keys.insert(def.id.as_str());
    }
    let inline_ids: BTreeSet<&str> = inline.iter().map(|def| def.id.as_str()).collect();

    // Resolve each journey subflow reference source, and reject a duplicate alias id (a
    // `subflow_call` step could not resolve unambiguously between two same-named references).
    let mut seen_aliases: BTreeSet<&str> = BTreeSet::new();
    if let Some(refs) = &doc.subflows {
        for (index, subflow_ref) in refs.iter().enumerate() {
            if !seen_aliases.insert(subflow_ref.id.as_str()) {
                errors.push(JourneyError::DuplicateSubflowRef {
                    pointer: format!("/subflows/{index}/id"),
                    id: subflow_ref.id.clone(),
                });
            }
            match &subflow_ref.source {
                SubflowSource::Builtin { name } => {
                    if !builtins.contains_key(name.as_str()) {
                        errors.push(JourneyError::UnknownBuiltinSubflow {
                            pointer: format!("/subflows/{index}/source"),
                            name: name.clone(),
                        });
                    }
                }
                SubflowSource::Inline { subflow_id } => {
                    if !inline_ids.contains(subflow_id.as_str()) {
                        errors.push(JourneyError::UnknownSubflowDefinition {
                            pointer: format!("/subflows/{index}/source"),
                            subflow: subflow_id.clone(),
                        });
                    }
                }
            }
        }
    }

    // Validate each inline definition as a fragment.
    for (index, def) in inline.iter().enumerate() {
        let base = format!("/subflow_definitions/{index}");
        validate_subflow_fragment(def, &base, &all_keys, admit_builtin_only, errors);
    }

    // Reject reference cycles across the whole definition graph.
    detect_subflow_cycles(inline, &builtins, &all_keys, errors);
}

/// Validate one subflow definition as a fragment (issue #92, PR 3): the same structural rules a
/// journey obeys, adapted so the subflow's `exits` play the completion role a journey's terminal
/// steps play. A subflow declares no terminal step (it returns, it never mints a session), declares
/// at least one exit, and every exit names a declared leaf step (no outgoing transition within the
/// subflow). `base` is the RFC 6901 pointer to this definition; `all_keys` is the global subflow
/// definition key set a nested `subflow_call` resolves against.
fn validate_subflow_fragment(
    def: &Subflow,
    base: &str,
    all_keys: &BTreeSet<&str>,
    admit_builtin_only: bool,
    errors: &mut Vec<JourneyError>,
) {
    let ids = collect_step_ids(&def.steps, base, errors);

    for (index, step) in def.steps.iter().enumerate() {
        let step_ptr = format!("{base}/steps/{index}");
        check_kind_and_node_group(step, &step_ptr, admit_builtin_only, errors);
        if step.id.contains(NAMESPACE_SEPARATOR) {
            errors.push(JourneyError::ReservedStepIdSeparator {
                pointer: format!("{step_ptr}/id"),
                id: step.id.clone(),
            });
        }
        if step.kind.is_terminal() {
            errors.push(JourneyError::SubflowTerminalStep {
                pointer: format!("{step_ptr}/kind"),
                step: step.id.clone(),
            });
        }
        // A nested subflow_call resolves against the global definition key set (a built-in name or
        // an inline definition id), not against a journey alias list.
        match &step.subflow {
            Some(key) if !all_keys.contains(key.as_str()) => {
                errors.push(JourneyError::DanglingSubflowRef {
                    pointer: format!("{step_ptr}/subflow"),
                    subflow: key.clone(),
                });
            }
            _ => {}
        }
        check_attachment_coherence(step, &step_ptr, errors);
    }

    let entry_known = ids.contains(def.entry.as_str());
    if !entry_known {
        errors.push(JourneyError::UnknownEntry {
            pointer: format!("{base}/entry"),
        });
    }

    if def.exits.is_empty() {
        errors.push(JourneyError::SubflowNoExit {
            pointer: format!("{base}/exits"),
            subflow: def.id.clone(),
        });
    }
    let exit_set: BTreeSet<&str> = def.exits.iter().map(String::as_str).collect();
    for (index, exit) in def.exits.iter().enumerate() {
        if !ids.contains(exit.as_str()) {
            errors.push(JourneyError::UnknownSubflowExit {
                pointer: format!("{base}/exits/{index}"),
                exit: exit.clone(),
            });
        }
    }
    // An exit is a return leaf: it must not route onward within the subflow.
    for (index, transition) in def.transitions.iter().enumerate() {
        if exit_set.contains(transition.from.as_str()) {
            errors.push(JourneyError::SubflowExitNotLeaf {
                pointer: format!("{base}/transitions/{index}"),
                exit: transition.from.clone(),
            });
        }
    }

    check_transition_endpoints(&ids, &def.transitions, base, errors);
    if entry_known {
        check_reachability_and_dead_ends(
            &def.entry,
            &def.steps,
            &def.transitions,
            &ids,
            &exit_set,
            base,
            errors,
        );
    }
    check_predicates(&def.steps, &def.transitions, base, errors);
}

/// Detect a subflow reference cycle (issue #92, PR 3): a subflow that reaches itself by following
/// `subflow_call` steps directly or transitively. Reports the first inline definition (in document
/// order) that participates in a cycle, so composition is guaranteed to terminate. Only resolvable
/// edges enter the graph (a dangling reference is reported separately), and a built-in subflow is a
/// node too (it can never close a cycle today, but the graph stays complete).
fn detect_subflow_cycles(
    inline: &[Subflow],
    builtins: &BTreeMap<String, Subflow>,
    all_keys: &BTreeSet<&str>,
    errors: &mut Vec<JourneyError>,
) {
    let mut graph: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for def in inline {
        graph.insert(def.id.clone(), called_keys(&def.steps, all_keys));
    }
    for (name, def) in builtins {
        graph.insert(name.clone(), called_keys(&def.steps, all_keys));
    }
    for (index, def) in inline.iter().enumerate() {
        if reaches(&graph, &def.id, &def.id) {
            errors.push(JourneyError::SubflowCycle {
                pointer: format!("/subflow_definitions/{index}"),
                subflow: def.id.clone(),
            });
            return;
        }
    }
}

/// The resolvable subflow definition keys a step slice calls, in document order (an unresolvable
/// reference is dropped from the graph, so a cycle check never trips on a dangling edge).
fn called_keys(steps: &[Step], all_keys: &BTreeSet<&str>) -> Vec<String> {
    let mut keys = Vec::new();
    for step in steps {
        if matches!(step.kind, StepKind::SubflowCall) {
            if let Some(key) = &step.subflow {
                if all_keys.contains(key.as_str()) {
                    keys.push(key.clone());
                }
            }
        }
    }
    keys
}

/// Whether `to` is reachable from `from` by at least one edge in the definition graph (a self-loop
/// or a longer cycle back to `from` when `from == to`). An iterative walk, so a cyclic graph cannot
/// exhaust the stack.
fn reaches(graph: &BTreeMap<String, Vec<String>>, from: &str, to: &str) -> bool {
    let mut visited: BTreeSet<&str> = BTreeSet::new();
    let mut stack: Vec<&str> = graph
        .get(from)
        .map(|next| next.iter().map(String::as_str).collect())
        .unwrap_or_default();
    while let Some(node) = stack.pop() {
        if node == to {
            return true;
        }
        if !visited.insert(node) {
            continue;
        }
        if let Some(next) = graph.get(node) {
            stack.extend(next.iter().map(String::as_str));
        }
    }
    false
}

/// Compose a journey into a flat, self-contained journey (issue #92, PR 3): a pure, load-time
/// splice that inlines every subflow at its call site so the result is a single journey with no
/// remaining `subflow_call` step. The journey is validated first (so its references resolve and its
/// subflow graph is acyclic), then each `subflow_call` step is expanded: the transitions that
/// targeted the call step are redirected to the subflow's entry, and each of the call step's
/// outgoing transitions (the return edges) is grafted onto every subflow exit. A subflow's steps
/// are namespaced by the call step id (`<call_id>::<step_id>`), so the same subflow can be called
/// more than once without an id collision, and nested subflows expand transitively.
///
/// Comments survive composition: every subflow step keeps its comment on its namespaced step, and
/// the calling step's comment (if any) is preserved by prepending it to the subflow entry step's
/// comment (joined by a newline when the entry already carries one), so no comment is lost.
///
/// # Errors
///
/// The journey's own load-time validation failures ([`crate::validate`]) when the journey does not
/// validate; [`JourneyError::ComposedTooLarge`] when the splice would exceed [`MAX_COMPOSED_STEPS`]
/// (a pathological acyclic fan-out); and, as an enforced invariant, the composed journey's own
/// validation failures should the splice ever produce a malformed journey (a defense against a
/// future splice bug, so a caller never receives an unchecked composed journey).
pub fn compose(journey: &Journey) -> Result<Journey, Vec<JourneyError>> {
    compose_inner(journey, crate::validate::BUILTIN_ONLY_REJECTED)
}

/// Compose an EMBEDDED BUILT-IN journey into a flat journey (issue #92, PR 8a): identical to
/// [`compose`] except that the BUILT-IN-ONLY mint-family step kinds
/// ([`StepKind::is_builtin_only`]) are ADMITTED, so the built-in login/registration/recovery
/// journeys that converge onto the compiled table validate and splice. A custom-authored artifact
/// still uses [`compose`], which refuses those kinds.
///
/// # Errors
///
/// The same failures [`compose`] reports, minus the built-in-only rejection.
pub fn compose_builtin(journey: &Journey) -> Result<Journey, Vec<JourneyError>> {
    compose_inner(journey, crate::validate::BUILTIN_ONLY_ADMITTED)
}

/// Compose a journey into a flat journey (issue #92), with `admit_builtin_only` selecting the
/// custom ([`compose`]) or embedded built-in ([`compose_builtin`]) validation context.
pub(crate) fn compose_inner(
    journey: &Journey,
    admit_builtin_only: bool,
) -> Result<Journey, Vec<JourneyError>> {
    crate::validate::validate_inner(
        journey,
        crate::validate::RESERVED_IDS_REJECTED,
        admit_builtin_only,
    )?;

    let registry = full_registry(journey);
    let alias_to_key = alias_to_key(journey);

    let mut flat = Journey {
        schema_version: journey.schema_version.clone(),
        id: journey.id.clone(),
        engine_version: journey.engine_version,
        entry: journey.entry.clone(),
        comment: journey.comment.clone(),
        steps: journey.steps.clone(),
        transitions: journey.transitions.clone(),
        subflows: None,
        subflow_definitions: None,
    };

    // Normalize the journey's subflow_call steps from an alias to a definition key, so every
    // subflow_call in the working document (journey-level and, once inlined, nested) resolves the
    // same way.
    for step in &mut flat.steps {
        if matches!(step.kind, StepKind::SubflowCall) {
            if let Some(alias) = &step.subflow {
                if let Some(key) = alias_to_key.get(alias) {
                    step.subflow = Some(key.clone());
                }
            }
        }
    }

    // Inline until no subflow_call step remains. Acyclicity (checked above) guarantees termination,
    // and the step ceiling guarantees an acyclic fan-out fails LOAD instead of exhausting memory.
    while let Some(index) = flat
        .steps
        .iter()
        .position(|step| matches!(step.kind, StepKind::SubflowCall))
    {
        if flat.steps.len() > MAX_COMPOSED_STEPS {
            return Err(vec![JourneyError::ComposedTooLarge {
                limit: MAX_COMPOSED_STEPS,
            }]);
        }
        inline_one(&mut flat, index, &registry);
    }
    if flat.steps.len() > MAX_COMPOSED_STEPS {
        return Err(vec![JourneyError::ComposedTooLarge {
            limit: MAX_COMPOSED_STEPS,
        }]);
    }

    // Insurance: the composed journey is itself validated before it is returned, so the invariant
    // "compose output is always validate-clean" is enforced, not merely documented. The reserved
    // namespace separator is admitted here because composition mints the only legitimate `::` ids;
    // the built-in-only context is preserved so an embedded built-in's mint-family kinds survive
    // the re-validation.
    crate::validate::validate_inner(
        &flat,
        crate::validate::RESERVED_IDS_ADMITTED,
        admit_builtin_only,
    )?;

    Ok(flat)
}

/// The registry every subflow key resolves against for composition: every built-in subflow plus
/// every inline definition the artifact carries.
fn full_registry(journey: &Journey) -> BTreeMap<String, Subflow> {
    let mut registry = builtin_subflows();
    if let Some(defs) = &journey.subflow_definitions {
        for def in defs {
            registry.insert(def.id.clone(), def.clone());
        }
    }
    registry
}

/// The map from a journey subflow alias to the definition key it resolves to (a built-in name or an
/// inline definition id).
fn alias_to_key(journey: &Journey) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    if let Some(refs) = &journey.subflows {
        for subflow_ref in refs {
            let key = match &subflow_ref.source {
                SubflowSource::Builtin { name } => name.clone(),
                SubflowSource::Inline { subflow_id } => subflow_id.clone(),
            };
            map.insert(subflow_ref.id.clone(), key);
        }
    }
    map
}

/// Inline the `subflow_call` step at `index` into `flat`: splice the resolved subflow's steps
/// (namespaced by the call step id), redirect the call step's incoming transitions to the subflow
/// entry, and graft the call step's outgoing return edges onto every subflow exit.
fn inline_one(flat: &mut Journey, index: usize, registry: &BTreeMap<String, Subflow>) {
    let call = flat.steps[index].clone();
    let call_id = call.id.clone();
    let key = call
        .subflow
        .clone()
        .expect("a validated subflow_call step carries a subflow key");
    let subflow = registry
        .get(&key)
        .expect("a validated subflow key resolves in the registry")
        .clone();

    let prefix = format!("{call_id}{NAMESPACE_SEPARATOR}");
    let namespaced = |id: &str| format!("{prefix}{id}");
    let entry_ns = namespaced(&subflow.entry);
    let exits_ns: Vec<String> = subflow.exits.iter().map(|exit| namespaced(exit)).collect();

    // The call step's outgoing transitions are the return edges grafted onto every subflow exit.
    let return_edges: Vec<(String, Option<Predicate>, Option<String>)> = flat
        .transitions
        .iter()
        .filter(|transition| transition.from == call_id)
        .map(|transition| {
            (
                transition.to.clone(),
                transition.guard.clone(),
                transition.comment.clone(),
            )
        })
        .collect();

    // The namespaced subflow steps; the entry step also carries the call step's comment.
    let mut spliced_steps: Vec<Step> = Vec::with_capacity(subflow.steps.len());
    for step in &subflow.steps {
        let mut cloned = step.clone();
        cloned.id = namespaced(&step.id);
        if cloned.id == entry_ns {
            cloned.comment = prepend_comment(call.comment.as_deref(), cloned.comment);
        }
        spliced_steps.push(cloned);
    }

    // If the journey's entry was this call step, it becomes the subflow entry.
    if flat.entry == call_id {
        flat.entry.clone_from(&entry_ns);
    }

    // Replace the call step in place with the spliced subflow steps (a move, so the untouched steps
    // are neither cloned nor reallocated on each inline).
    flat.steps.splice(index..=index, spliced_steps);

    // Edit the transition list in place: drop the return edges (consumed), redirect incoming edges
    // to the subflow entry, then append the namespaced subflow transitions and the grafted returns.
    flat.transitions
        .retain(|transition| transition.from != call_id);
    for transition in &mut flat.transitions {
        if transition.to == call_id {
            transition.to.clone_from(&entry_ns);
        }
    }
    for transition in &subflow.transitions {
        flat.transitions.push(Transition {
            from: namespaced(&transition.from),
            to: namespaced(&transition.to),
            guard: transition.guard.clone(),
            comment: transition.comment.clone(),
        });
    }
    for exit in &exits_ns {
        for (to, guard, comment) in &return_edges {
            flat.transitions.push(Transition {
                from: exit.clone(),
                to: to.clone(),
                guard: guard.clone(),
                comment: comment.clone(),
            });
        }
    }
}

/// Combine the calling step's comment with the subflow entry step's comment so neither is lost: the
/// call comment is prepended, joined by a newline when the entry already carries one.
fn prepend_comment(call: Option<&str>, entry: Option<String>) -> Option<String> {
    match (call, entry) {
        (Some(call), Some(entry)) => Some(format!("{call}\n{entry}")),
        (Some(call), None) => Some(call.to_owned()),
        (None, entry) => entry,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{JOURNEY_ENGINE_VERSION, JOURNEY_SCHEMA_VERSION, SubflowRef, Transition};
    use crate::validate::validate;

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

    fn unguarded(from: &str, to: &str) -> Transition {
        Transition {
            from: from.to_owned(),
            to: to.to_owned(),
            guard: None,
            comment: None,
        }
    }

    /// A journey that calls the built-in `mfa_step_up` subflow via an alias, then completes.
    fn journey_calling_builtin(id: &str) -> Journey {
        Journey {
            schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
            id: id.to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            entry: "primary".to_owned(),
            comment: None,
            steps: vec![
                step("primary", StepKind::IdentifierPassword, Some("password")),
                Step {
                    subflow: Some("step_up".to_owned()),
                    comment: Some("Escalate to a second factor.".to_owned()),
                    ..step("call", StepKind::SubflowCall, None)
                },
                step("done", StepKind::Terminal, None),
            ],
            transitions: vec![unguarded("primary", "call"), unguarded("call", "done")],
            subflows: Some(vec![SubflowRef {
                id: "step_up".to_owned(),
                source: SubflowSource::Builtin {
                    name: BUILTIN_MFA_STEP_UP.to_owned(),
                },
            }]),
            subflow_definitions: None,
        }
    }

    #[test]
    fn the_builtin_mfa_step_up_is_a_well_formed_fragment() {
        let mut errors = Vec::new();
        let builtins = builtin_subflows();
        let all_keys: BTreeSet<&str> = builtins.keys().map(String::as_str).collect();
        validate_subflow_fragment(
            &mfa_step_up(),
            "/subflow_definitions/0",
            &all_keys,
            crate::validate::BUILTIN_ONLY_REJECTED,
            &mut errors,
        );
        assert_eq!(errors, Vec::new());
    }

    #[test]
    fn a_journey_calling_the_builtin_validates_and_composes() {
        let journey = journey_calling_builtin("login_with_step_up");
        assert_eq!(validate(&journey), Ok(()));

        // compose() re-validates its output internally (admitting the reserved namespace
        // separator it mints), so a successful compose already guarantees a validate-clean journey;
        // the public validate() would refuse the legitimate `::` ids composition produces.
        let composed = compose(&journey).expect("composition succeeds");
        // No subflow_call step remains.
        assert!(
            composed
                .steps
                .iter()
                .all(|step| !matches!(step.kind, StepKind::SubflowCall))
        );
        // The composed journey passes the structural validation with reserved ids admitted.
        assert_eq!(
            crate::validate::validate_inner(
                &composed,
                crate::validate::RESERVED_IDS_ADMITTED,
                crate::validate::BUILTIN_ONLY_REJECTED
            ),
            Ok(())
        );
        // Control routes into the subflow entry and back to the caller's continuation.
        assert!(
            composed
                .steps
                .iter()
                .any(|step| step.id == "call::challenge")
        );
        assert!(
            composed
                .transitions
                .iter()
                .any(|t| t.from == "primary" && t.to == "call::challenge")
        );
        assert!(
            composed
                .transitions
                .iter()
                .any(|t| t.from == "call::challenge" && t.to == "done")
        );
    }

    #[test]
    fn the_same_definition_is_shared_by_two_journeys() {
        // One inline definition referenced by two journeys: both validate and compose against the
        // same fragment (edit-once-both-change, minus version pinning).
        let definition = Subflow {
            id: "verify_email".to_owned(),
            entry: "collect".to_owned(),
            exits: vec!["collect".to_owned()],
            comment: Some("Collect and verify an email factor.".to_owned()),
            steps: vec![Step {
                comment: Some("Collect the email one-time code.".to_owned()),
                ..step("collect", StepKind::MfaChallenge, Some("email_otp"))
            }],
            transitions: vec![],
        };
        let make = |id: &str| Journey {
            schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
            id: id.to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            entry: "primary".to_owned(),
            comment: None,
            steps: vec![
                step("primary", StepKind::IdentifierPassword, Some("password")),
                Step {
                    subflow: Some("verify_email".to_owned()),
                    ..step("call", StepKind::SubflowCall, None)
                },
                step("done", StepKind::Terminal, None),
            ],
            transitions: vec![unguarded("primary", "call"), unguarded("call", "done")],
            subflows: Some(vec![SubflowRef {
                id: "verify_email".to_owned(),
                source: SubflowSource::Inline {
                    subflow_id: "verify_email".to_owned(),
                },
            }]),
            subflow_definitions: Some(vec![definition.clone()]),
        };
        let first = make("journey_one");
        let second = make("journey_two");
        assert_eq!(validate(&first), Ok(()));
        assert_eq!(validate(&second), Ok(()));
        // Both compose against the identical fragment: the same namespaced entry step appears.
        let composed_first = compose(&first).expect("compose first");
        let composed_second = compose(&second).expect("compose second");
        assert!(composed_first.steps.iter().any(|s| s.id == "call::collect"));
        assert!(
            composed_second
                .steps
                .iter()
                .any(|s| s.id == "call::collect")
        );
    }

    #[test]
    fn subflow_step_and_call_comments_survive_composition() {
        let journey = journey_calling_builtin("commented");
        let composed = compose(&journey).expect("compose");
        let entry = composed
            .steps
            .iter()
            .find(|step| step.id == "call::challenge")
            .expect("the namespaced subflow entry step is present");
        let comment = entry
            .comment
            .as_deref()
            .expect("the entry carries a comment");
        // The subflow step's own comment survives verbatim.
        assert!(comment.contains("Present the enrolled second factor."));
        // The calling step's comment is preserved by prepending it, so nothing is lost.
        assert!(comment.contains("Escalate to a second factor."));
    }

    /// An inline definition whose two steps form a cycle back to a nested subflow call, for the
    /// transitive-cycle test.
    fn calling_definition(id: &str, calls: &str, tail: &str) -> Subflow {
        Subflow {
            id: id.to_owned(),
            entry: "call".to_owned(),
            exits: vec![tail.to_owned()],
            comment: None,
            steps: vec![
                Step {
                    subflow: Some(calls.to_owned()),
                    ..step("call", StepKind::SubflowCall, None)
                },
                step(tail, StepKind::IdentifierPassword, Some("password")),
            ],
            transitions: vec![unguarded("call", tail)],
        }
    }

    fn journey_referencing(def_id: &str, definitions: Vec<Subflow>) -> Journey {
        Journey {
            schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
            id: "cyclic".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            entry: "primary".to_owned(),
            comment: None,
            steps: vec![
                step("primary", StepKind::IdentifierPassword, Some("password")),
                Step {
                    subflow: Some(def_id.to_owned()),
                    ..step("call", StepKind::SubflowCall, None)
                },
                step("done", StepKind::Terminal, None),
            ],
            transitions: vec![unguarded("primary", "call"), unguarded("call", "done")],
            subflows: Some(vec![SubflowRef {
                id: def_id.to_owned(),
                source: SubflowSource::Inline {
                    subflow_id: def_id.to_owned(),
                },
            }]),
            subflow_definitions: Some(definitions),
        }
    }

    #[test]
    fn a_directly_recursive_subflow_is_rejected() {
        // A subflow whose nested subflow_call names itself.
        let definition = calling_definition("loops", "loops", "tail");
        let journey = journey_referencing("loops", vec![definition]);
        let errors = validate(&journey).expect_err("a self-referencing subflow is rejected");
        assert!(
            errors.iter().any(|error| matches!(
                error,
                JourneyError::SubflowCycle { subflow, .. } if subflow == "loops"
            )),
            "expected a SubflowCycle, got {errors:?}"
        );
    }

    #[test]
    fn a_transitively_recursive_subflow_is_rejected() {
        // A calls B and B calls A.
        let a = calling_definition("alpha", "beta", "a_tail");
        let b = calling_definition("beta", "alpha", "b_tail");
        let journey = journey_referencing("alpha", vec![a, b]);
        let errors = validate(&journey).expect_err("a transitively cyclic subflow is rejected");
        assert!(
            errors
                .iter()
                .any(|error| matches!(error, JourneyError::SubflowCycle { .. })),
            "expected a SubflowCycle, got {errors:?}"
        );
    }

    #[test]
    fn a_subflow_call_to_an_undefined_inline_definition_is_rejected() {
        // The alias is declared, but its Inline source names no carried definition.
        let journey = Journey {
            schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
            id: "dangling".to_owned(),
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
                id: "ghost".to_owned(),
                source: SubflowSource::Inline {
                    subflow_id: "ghost".to_owned(),
                },
            }]),
            subflow_definitions: None,
        };
        assert_eq!(
            validate(&journey),
            Err(vec![JourneyError::UnknownSubflowDefinition {
                pointer: "/subflows/0/source".to_owned(),
                subflow: "ghost".to_owned(),
            }])
        );
    }

    #[test]
    fn a_terminal_step_inside_a_subflow_is_rejected() {
        let definition = Subflow {
            id: "has_terminal".to_owned(),
            entry: "collect".to_owned(),
            exits: vec!["collect".to_owned()],
            comment: None,
            steps: vec![
                step("collect", StepKind::MfaChallenge, Some("totp")),
                step("end", StepKind::Terminal, None),
            ],
            transitions: vec![],
        };
        let journey = journey_referencing("has_terminal", vec![definition]);
        let errors = validate(&journey).expect_err("a terminal inside a subflow is rejected");
        assert!(
            errors.iter().any(|error| matches!(
                error,
                JourneyError::SubflowTerminalStep { step, .. } if step == "end"
            )),
            "expected a SubflowTerminalStep, got {errors:?}"
        );
    }

    #[test]
    fn an_ill_typed_guard_in_a_subflow_fails_load() {
        // The predicate type check runs over a subflow's transition guards: an ordering operator on
        // a boolean signal is a load-time type error located inside the definition.
        use crate::artifact::{CmpOp, FieldRef, FieldSource, Literal, Predicate};
        let definition = Subflow {
            id: "bad_guard".to_owned(),
            entry: "branch".to_owned(),
            exits: vec!["leaf".to_owned()],
            comment: None,
            steps: vec![
                step("branch", StepKind::MfaChallenge, Some("totp")),
                step("leaf", StepKind::IdentifierPassword, Some("password")),
            ],
            transitions: vec![Transition {
                from: "branch".to_owned(),
                to: "leaf".to_owned(),
                guard: Some(Predicate::Cmp {
                    field: FieldRef {
                        source: FieldSource::Signals,
                        pointer: "/mfa_required".to_owned(),
                    },
                    op: CmpOp::Lt,
                    value: Literal::Bool(true),
                }),
                comment: None,
            }],
        };
        let journey = journey_referencing("bad_guard", vec![definition]);
        let errors = validate(&journey).expect_err("an ill-typed subflow guard is rejected");
        assert!(
            errors
                .iter()
                .any(|error| matches!(error, JourneyError::PredicateType(_))),
            "expected a PredicateType error, got {errors:?}"
        );
    }

    #[test]
    fn an_author_step_id_using_the_reserved_separator_is_rejected() {
        // An author names a step exactly like a namespaced subflow step; without the reserved-id
        // rule this would validate as input yet collide after composition. The rule refuses it at
        // load with a precise pointer.
        let journey = Journey {
            schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
            id: "collision".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            entry: "primary".to_owned(),
            comment: None,
            steps: vec![
                step("primary", StepKind::IdentifierPassword, Some("password")),
                Step {
                    subflow: Some("step_up".to_owned()),
                    ..step("call", StepKind::SubflowCall, None)
                },
                step("call::challenge", StepKind::MfaChallenge, Some("totp")),
                step("done", StepKind::Terminal, None),
            ],
            transitions: vec![
                unguarded("primary", "call"),
                unguarded("call", "call::challenge"),
                unguarded("call::challenge", "done"),
            ],
            subflows: Some(vec![SubflowRef {
                id: "step_up".to_owned(),
                source: SubflowSource::Builtin {
                    name: BUILTIN_MFA_STEP_UP.to_owned(),
                },
            }]),
            subflow_definitions: None,
        };
        let errors = validate(&journey).expect_err("a reserved-separator step id is rejected");
        assert!(
            errors.iter().any(|error| matches!(
                error,
                JourneyError::ReservedStepIdSeparator { id, .. } if id == "call::challenge"
            )),
            "expected a ReservedStepIdSeparator, got {errors:?}"
        );
    }

    #[test]
    fn a_duplicate_subflow_reference_alias_is_rejected() {
        // Two references share the alias `dup`: a subflow_call could not resolve unambiguously.
        let journey = Journey {
            schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
            id: "dup_alias".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            entry: "primary".to_owned(),
            comment: None,
            steps: vec![
                step("primary", StepKind::IdentifierPassword, Some("password")),
                Step {
                    subflow: Some("dup".to_owned()),
                    ..step("call", StepKind::SubflowCall, None)
                },
                step("done", StepKind::Terminal, None),
            ],
            transitions: vec![unguarded("primary", "call"), unguarded("call", "done")],
            subflows: Some(vec![
                SubflowRef {
                    id: "dup".to_owned(),
                    source: SubflowSource::Builtin {
                        name: BUILTIN_MFA_STEP_UP.to_owned(),
                    },
                },
                SubflowRef {
                    id: "dup".to_owned(),
                    source: SubflowSource::Inline {
                        subflow_id: "other".to_owned(),
                    },
                },
            ]),
            subflow_definitions: None,
        };
        let errors = validate(&journey).expect_err("a duplicate alias is rejected");
        assert!(
            errors.iter().any(|error| matches!(
                error,
                JourneyError::DuplicateSubflowRef { id, .. } if id == "dup"
            )),
            "expected a DuplicateSubflowRef, got {errors:?}"
        );
    }

    #[test]
    fn an_acyclic_fan_out_that_exceeds_the_ceiling_fails_load_without_hanging() {
        // Each of N inline definitions calls the next TWICE, an acyclic DAG that would expand to
        // 2^N steps. The step ceiling makes it FAIL LOAD rather than hang or exhaust memory.
        let n = 20;
        let mut definitions: Vec<Subflow> = Vec::new();
        for i in 0..n {
            let next = format!("level_{}", i + 1);
            let (first, second) = if i + 1 < n {
                (
                    Step {
                        subflow: Some(next.clone()),
                        ..step("call_a", StepKind::SubflowCall, None)
                    },
                    Step {
                        subflow: Some(next.clone()),
                        ..step("call_b", StepKind::SubflowCall, None)
                    },
                )
            } else {
                // The deepest level is a plain leaf, so the graph is strictly acyclic.
                (
                    step("call_a", StepKind::MfaChallenge, Some("totp")),
                    step("call_b", StepKind::MfaChallenge, Some("totp")),
                )
            };
            definitions.push(Subflow {
                id: format!("level_{i}"),
                entry: "call_a".to_owned(),
                exits: vec!["tail".to_owned()],
                comment: None,
                steps: vec![
                    first,
                    second,
                    step("tail", StepKind::IdentifierPassword, Some("password")),
                ],
                transitions: vec![unguarded("call_a", "call_b"), unguarded("call_b", "tail")],
            });
        }
        let journey = journey_referencing("level_0", definitions);
        // The journey itself validates (the DAG is acyclic); composition refuses the blow-up.
        assert_eq!(validate(&journey), Ok(()));
        assert_eq!(
            compose(&journey),
            Err(vec![JourneyError::ComposedTooLarge {
                limit: MAX_COMPOSED_STEPS,
            }])
        );
    }

    #[test]
    fn a_normal_multi_subflow_journey_stays_under_the_ceiling() {
        // A chain of three inline definitions composes well within the ceiling.
        let leaf = Subflow {
            id: "leaf".to_owned(),
            entry: "work".to_owned(),
            exits: vec!["work".to_owned()],
            comment: None,
            steps: vec![step("work", StepKind::MfaChallenge, Some("totp"))],
            transitions: vec![],
        };
        let middle = calling_definition("middle", "leaf", "m_tail");
        let outer = calling_definition("outer", "middle", "o_tail");
        let journey = journey_referencing("outer", vec![outer, middle, leaf]);
        let composed = compose(&journey).expect("a small chain composes");
        assert!(composed.steps.len() < MAX_COMPOSED_STEPS);
    }
}
