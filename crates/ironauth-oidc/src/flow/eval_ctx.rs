// SPDX-License-Identifier: MIT OR Apache-2.0

//! The custom-journey evaluation-context assembly (issue #92, PR 4): the ONE place the engine
//! populates the PR 2 [`EvalContext`] from real flow state, so the pure predicate
//! [`evaluate`](ironauth_journey::evaluate) can route a custom journey's guarded transitions.
//!
//! ## I/O at assembly, a pure evaluate
//!
//! Every read (the subject's sealed trait document, the risk decision) happens HERE, at
//! assembly, so [`ironauth_journey::evaluate`] stays a pure, total function over the assembled
//! context. A guard references trait POINTERS and group / scope NAMES only, never a secret, so
//! nothing sensitive rides a guard.
//!
//! The signals the executor emitted (`primary_verified`, `mfa_required`, `enroll_required`,
//! `profiling_pending`) are the boolean routing outputs the built-in login / MFA / profiling
//! executor cores produce; the engine folds them into the flow context so a transition guard can
//! route on them exactly as the built-in login journey's imperative router branches on the same
//! decisions.

use std::collections::BTreeSet;

use serde_json::Value;

use ironauth_journey::{EvalContext, FlowContext, RiskLevel, RiskView, SignalSet};
use ironauth_store::{Scope, UserId};

use super::PersistedState;
use crate::state::OidcState;

/// Assemble the typed evaluation context for a custom-journey routing decision (issue #92, PR
/// 4): populate the PR 2 [`EvalContext`] SHAPE from the flow's real server-side state. The
/// current step id, the proven method tokens, and the blind subject handle come from the
/// persisted flow scratch; the outcome signals come from the executor that just ran; the subject
/// traits come from the #53 sealed trait document (null before a primary factor authenticates a
/// subject); and the `risk` view is threaded in from the executor that just ran (issue #355): the
/// login step carries its real risk verdict, every other hop carries the default Low.
///
/// The subject groups and scopes are left empty: they have no live engine source, so
/// [`ironauth_journey`]'s `source_is_engine_live` marks them NOT-LIVE and the load-time validator
/// REFUSES any guard that reads them (fail-closed at authoring, issue #355). The empties are
/// therefore unreachable by any validated guard, never a silent misroute and never fail-open.
pub(super) async fn assemble_eval_context(
    state: &OidcState,
    scope: Scope,
    step_id: &str,
    scratch: &PersistedState,
    signals: &SignalSet,
    risk: RiskView,
) -> EvalContext {
    // The subject's sealed trait document, read at assembly so evaluate stays pure. An absent
    // subject (pre-primary) or an unreadable document resolves to JSON null, which the evaluator
    // treats by its documented total null rule (never a panic, never fail-open).
    let subject_traits = subject_traits(state, scope, scratch.subject.as_deref()).await;

    let method_tokens: BTreeSet<String> = scratch.methods.iter().cloned().collect();
    let flow = FlowContext {
        step_id: step_id.to_owned(),
        method_tokens,
        subject_handle: scratch.subject.clone().unwrap_or_default(),
        signals: signals.clone(),
    };

    EvalContext {
        flow,
        subject_traits,
        // No live engine source: `source_is_engine_live` marks `subject_groups` / `subject_scopes`
        // NOT-LIVE, so the load-time validator refuses any guard reading them (issue #355). The
        // empties are unreachable by any validated guard, so a `Member` guard is never a silent
        // misroute and never fail-open.
        subject_groups: BTreeSet::new(),
        subject_scopes: BTreeSet::new(),
        risk,
    }
}

/// The subject's sealed trait document, or JSON null when there is no subject yet or the read
/// faults. The read happens at context assembly (the ONE I/O edge); the evaluator itself is pure.
async fn subject_traits(state: &OidcState, scope: Scope, subject: Option<&str>) -> Value {
    let Some(subject) = subject else {
        return Value::Null;
    };
    let Ok(subject_id) = UserId::parse_in_scope(subject, &scope) else {
        return Value::Null;
    };
    match state
        .store()
        .scoped(scope)
        .users()
        .traits(&subject_id)
        .await
    {
        Ok(Some((_, doc))) => doc,
        _ => Value::Null,
    }
}

/// Map the flow's risk decision level to the evaluator's [`RiskView`] (issue #355): the risk level
/// a custom-journey guard routes on, threaded in from the login step that computed it. Only the
/// categorical `/level` is engine-live (`source_is_engine_live`), so the numeric score is left
/// zero; a guard on `/score` is validator-rejected at load time and can never reach this value.
pub(super) fn risk_view_from_level(level: crate::risk::RiskLevel) -> RiskView {
    let level = match level {
        crate::risk::RiskLevel::Low => RiskLevel::Low,
        crate::risk::RiskLevel::Med => RiskLevel::Medium,
        crate::risk::RiskLevel::High => RiskLevel::High,
    };
    RiskView { level, score: 0 }
}
