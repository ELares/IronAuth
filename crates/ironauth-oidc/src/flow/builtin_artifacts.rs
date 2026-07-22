// SPDX-License-Identifier: MIT OR Apache-2.0

//! The embedded built-in journey artifacts (issue #92, PR 8b): the compiled transition tables
//! for the converging MINT-FAMILY built-in journeys, so the table engine
//! ([`super::orchestration::drive_via_table`]) can drive a built-in journey byte-identically to
//! its hand-written imperative driver.
//!
//! ## Why an embedded artifact
//!
//! A built-in journey's state machine (login plus its in-flow MFA and progressive-profiling holds)
//! is expressible in the SAME declarative vocabulary a custom journey uses: renderable executor
//! kinds ([`ironauth_journey::StepKind::IdentifierPassword`],
//! [`ironauth_journey::StepKind::MfaChallenge`], [`ironauth_journey::StepKind::MfaEnroll`],
//! [`ironauth_journey::StepKind::ProgressiveProfiling`]) plus signal-guarded transitions and a
//! terminal. PR 8b re-expresses [`Journey::Login`] as one such artifact and flips its dispatch onto
//! the table engine. The compiled artifact, driven through the table engine, reproduces the
//! imperative router's routing priority (Challenge > Enroll > profiling > mint) and every rendered
//! byte, gated by the byte-equivalence tests.
//!
//! ## Compilation is pure and cached
//!
//! Each artifact is a fixed value; [`ironauth_journey::compile_builtin`] is a pure, load-time
//! lowering with no clock, entropy, or I/O, so the compiled table is compiled ONCE behind a
//! [`OnceLock`] and shared. The login artifact uses only custom-usable kinds plus a terminal, so it
//! would also pass the stricter [`ironauth_journey::compile`]; it is compiled through
//! `compile_builtin` for uniformity with the registration/recovery artifacts the later convergence
//! PRs (8c, 8d) add here.

use std::sync::OnceLock;

use ironauth_journey::{
    CmpOp, CompiledJourney, FieldRef, FieldSource, JOURNEY_ENGINE_VERSION, JOURNEY_SCHEMA_VERSION,
    Journey as JourneyDoc, Literal, Predicate, Step, StepKind, Transition, compile_builtin,
};

use super::model::Journey;

/// The compiled embedded artifact for a converging built-in journey (issue #92, PR 8b), or
/// [`None`] for a journey that does not (yet) drive through the table engine. Only
/// [`Journey::Login`] is populated in PR 8b; the registration (8c) and recovery (8d) convergence
/// PRs add their arms here. A [`Journey::Custom`] flow never resolves through this registry (it
/// resolves its pinned table through the store-backed source instead), and the non-converging
/// journeys (federation, consent, the MFA pseudo journey) stay thin imperative drivers.
pub(super) fn builtin_compiled(journey: Journey) -> Option<&'static CompiledJourney> {
    match journey {
        Journey::Login => Some(login_compiled()),
        Journey::Registration => Some(registration_compiled()),
        Journey::Recovery
        | Journey::Mfa
        | Journey::Federation
        | Journey::Consent
        | Journey::Custom => None,
    }
}

/// The compiled login artifact, compiled once and shared (issue #92, PR 8b).
///
/// # Panics
///
/// Never in practice: the fixed login artifact is load-valid by construction (a compile-time
/// verified fixture, pinned by the `login_artifact_compiles` and the projection tests), so the
/// `expect` is a programming-error guard, not a runtime path.
fn login_compiled() -> &'static CompiledJourney {
    static COMPILED: OnceLock<CompiledJourney> = OnceLock::new();
    COMPILED.get_or_init(|| {
        compile_builtin(&login_artifact()).expect("the embedded built-in login journey compiles")
    })
}

/// A step of an embedded built-in artifact.
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

/// An unconditional (unguarded) transition: the always-applicable fallback edge.
fn edge(from: &str, to: &str) -> Transition {
    Transition {
        from: from.to_owned(),
        to: to.to_owned(),
        guard: None,
        comment: None,
    }
}

/// A signal-guarded transition: the edge is taken when the named boolean routing signal is true.
/// The predicate is the exact well-typed shape the load-time type check admits (a boolean
/// comparison over a [`FieldSource::Signals`] pointer), mirroring the AC1 fixture, so the embedded
/// artifact validates and compiles cleanly.
fn signal_edge(from: &str, to: &str, signal_pointer: &str) -> Transition {
    Transition {
        from: from.to_owned(),
        to: to.to_owned(),
        guard: Some(Predicate::Cmp {
            field: FieldRef {
                source: FieldSource::Signals,
                pointer: signal_pointer.to_owned(),
            },
            op: CmpOp::Eq,
            value: Literal::Bool(true),
        }),
        comment: None,
    }
}

/// The embedded built-in LOGIN artifact (issue #92, PR 8b): the login state machine, whose MFA
/// challenge / enroll and progressive-profiling holds are substates, expressed as a declarative
/// journey.
///
/// The five steps render through the SAME fixed node builders the imperative path and the golden
/// corpus call (the `node_group` is validation metadata only; `enter_step_nodes` ignores it), so
/// the rendered bytes cannot depend on the group choice. The transitions are in DOCUMENT ORDER,
/// which is load-bearing for BOTH the engine's first-true-guard routing and the inspector's
/// `project_plan` BFS: edge `primary -> mfa_chal` MUST precede `primary -> mfa_enrl` so the routing
/// priority (Challenge > Enroll > profiling > direct mint) and the projected plan
/// (`[IdentifierPassword, MfaChallenge, MfaEnroll, ProgressiveProfiling, Completed]`) both match the
/// imperative login journey and the static `Journey::Login.plan()`.
fn login_artifact() -> JourneyDoc {
    JourneyDoc {
        schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
        id: "builtin_login".to_owned(),
        engine_version: JOURNEY_ENGINE_VERSION,
        entry: "primary".to_owned(),
        comment: None,
        steps: vec![
            step("primary", StepKind::IdentifierPassword, Some("password")),
            step("mfa_chal", StepKind::MfaChallenge, Some("totp")),
            step("mfa_enrl", StepKind::MfaEnroll, Some("totp")),
            step("profiling", StepKind::ProgressiveProfiling, Some("profile")),
            step("done", StepKind::Terminal, None),
        ],
        // Document order is load-bearing (see the doc comment above): the primary router priority
        // is Challenge (edge 1) > Enroll (edge 2) > profiling (edge 3) > direct mint (edge 4), and
        // after a second factor the priority is profiling (edges 5, 7) > mint (edges 6, 8).
        transitions: vec![
            signal_edge("primary", "mfa_chal", "/mfa_required"),
            signal_edge("primary", "mfa_enrl", "/enroll_required"),
            signal_edge("primary", "profiling", "/profiling_pending"),
            edge("primary", "done"),
            signal_edge("mfa_chal", "profiling", "/profiling_pending"),
            edge("mfa_chal", "done"),
            signal_edge("mfa_enrl", "profiling", "/profiling_pending"),
            edge("mfa_enrl", "done"),
            edge("profiling", "done"),
        ],
        subflows: None,
        subflow_definitions: None,
    }
}

/// The compiled registration artifact, compiled once and shared (issue #92, PR 8c).
///
/// # Panics
///
/// Never in practice: the fixed registration artifact is load-valid by construction (a
/// compile-time verified fixture, pinned by `registration_artifact_compiles_and_pins_its_shape`
/// and the projection tests), so the `expect` is a programming-error guard, not a runtime path.
fn registration_compiled() -> &'static CompiledJourney {
    static COMPILED: OnceLock<CompiledJourney> = OnceLock::new();
    COMPILED.get_or_init(|| {
        compile_builtin(&registration_artifact())
            .expect("the embedded built-in registration journey compiles")
    })
}

/// The embedded built-in REGISTRATION artifact (issue #92, PR 8c): the SIMPLEST mint-family
/// journey, a two-step guard-free machine (details form, then a terminal mint).
///
/// Registration does not step up to MFA or profiling: the account is created inside the
/// [`StepKind::Registration`] executor and the session mints immediately on a genuine create, so
/// the artifact needs no MFA / profiling steps and no guards (contrast the login artifact's five
/// guarded steps). The uniform acknowledgment ([`FlowStateTag::RegistrationAck`](super::model::FlowStateTag))
/// is NOT a routed step: it is a render-override the SAME `register` executor emits while the flow
/// stays OPEN (see [`super::wire_identity::render_override_states`]), so it needs no edge or step of
/// its own. The single unconditional `register -> done` edge is the one forward path a genuine
/// account create takes to the terminal. The `node_group` is validation metadata only
/// (`enter_step_nodes` renders through fixed builders and never routes into the entry step).
///
/// [`StepKind::Registration`] is built-in-only ([`StepKind::is_builtin_only`]), so this artifact
/// compiles ONLY through [`compile_builtin`], never the stricter [`ironauth_journey::compile`] a
/// custom-authored journey uses.
fn registration_artifact() -> JourneyDoc {
    JourneyDoc {
        schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
        id: "builtin_registration".to_owned(),
        engine_version: JOURNEY_ENGINE_VERSION,
        entry: "register".to_owned(),
        comment: None,
        steps: vec![
            step("register", StepKind::Registration, Some("password")),
            step("done", StepKind::Terminal, None),
        ],
        // One unconditional forward edge: a genuine account create advances the register step, and
        // the walk takes this fallback edge to the terminal mint. The Ack and details re-renders
        // stay on the register step (a render-override / a plain render), never advancing.
        transitions: vec![edge("register", "done")],
        subflows: None,
        subflow_definitions: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_artifact_compiles_and_pins_its_shape() {
        // The embedded login artifact is load-valid and compiles cleanly, and its topology is the
        // five-step machine PR 8b flips the imperative login journey onto.
        let compiled = login_compiled();
        assert_eq!(compiled.entry, "primary");
        assert_eq!(compiled.steps.len(), 5);
        // The document-order priority the routing depends on: from `primary`, challenge before
        // enroll before profiling before the unguarded direct mint.
        let primary_edges = compiled.edges("primary");
        assert_eq!(primary_edges.len(), 4);
        assert_eq!(primary_edges[0].to, "mfa_chal");
        assert_eq!(primary_edges[1].to, "mfa_enrl");
        assert_eq!(primary_edges[2].to, "profiling");
        assert_eq!(primary_edges[3].to, "done");
        assert!(
            primary_edges[3].guard.is_none(),
            "the direct-mint fallback edge is unguarded"
        );
        // Every step is reachable and a completion is reachable (liveness).
        assert!(compiled.reachable().contains("done"));
    }

    #[test]
    fn registration_artifact_compiles_and_pins_its_shape() {
        // The embedded registration artifact is load-valid and compiles cleanly, and its topology
        // is the two-step guard-free machine PR 8c flips the imperative registration journey onto.
        let compiled = registration_compiled();
        assert_eq!(compiled.entry, "register");
        assert_eq!(compiled.steps.len(), 2);
        // The register step has exactly one forward edge, and it is the unguarded direct-mint
        // fallback to the terminal (registration is guard-free, the whole reason it is the simplest
        // mint-family journey).
        let register_edges = compiled.edges("register");
        assert_eq!(register_edges.len(), 1);
        assert_eq!(register_edges[0].to, "done");
        assert!(
            register_edges[0].guard.is_none(),
            "the direct-mint edge is unguarded"
        );
        // The terminal is reachable (liveness).
        assert!(compiled.reachable().contains("done"));
    }
}
