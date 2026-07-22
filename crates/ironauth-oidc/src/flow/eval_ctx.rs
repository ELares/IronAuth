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
/// subject); and the risk view is mapped from the risk compute core's decision (Low pre-mint,
/// with no live signals to raise it). The subject groups and scopes are wired in PR 5 (the admin
/// journey store lands the membership sources); a `Member` guard resolves to `false` against the
/// empty sets until then, which is type-safe (never fail-open).
pub(super) async fn assemble_eval_context(
    state: &OidcState,
    scope: Scope,
    step_id: &str,
    scratch: &PersistedState,
    signals: &SignalSet,
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
        // PR 5 wiring: the subject's group and scope memberships. Empty until then, so a `Member`
        // guard is a type-safe `false` (the load-time type check already guarantees only a group
        // set reads `subject_groups` and only a scope set reads `subject_scopes`).
        subject_groups: BTreeSet::new(),
        subject_scopes: BTreeSet::new(),
        risk: risk_view(),
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

/// The risk view a custom-journey guard reads (issue #92, PR 4): the risk compute core's decision
/// mapped to the evaluator's [`RiskView`]. Pre-mint, the flow carries no live risk signals, so the
/// compute core's default decision is `Low`; a later PR that threads live signals into the flow
/// raises it here without any evaluator change. The numeric score has no pre-mint source, so it
/// is zero.
fn risk_view() -> RiskView {
    let decision = crate::risk::decide_from_signals(Vec::new(), false, None, false, false);
    let level = match decision.level {
        crate::risk::RiskLevel::Low => RiskLevel::Low,
        crate::risk::RiskLevel::Med => RiskLevel::Medium,
        crate::risk::RiskLevel::High => RiskLevel::High,
    };
    RiskView { level, score: 0 }
}
