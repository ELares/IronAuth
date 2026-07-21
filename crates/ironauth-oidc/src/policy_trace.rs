// SPDX-License-Identifier: MIT OR Apache-2.0

//! Policy decision trace capture (issue #91, M9 flow inspector).
//!
//! The admin flow inspector surfaces WHY a policy decision came out the way it did:
//! the step up authentication evaluation (RFC 9470, issue #72), the risk scoring
//! decision (issue #79), and the connector claim mapping evaluation (issue #75). This
//! module records each of those three decisions as a STRUCTURALLY REDACTED safe field
//! trace into the `policy_decision_traces` sink, plus a token size (claim bloat) event
//! into the `token_size_events` sink, entirely OFF the decision path.
//!
//! Every capture here is BEST EFFORT: a failure to record is logged and swallowed, so a
//! trace can never change the policy decision or any wire behavior. Capture is VERBOSITY
//! GATED: at `off` recording is a no op (nothing is written; the decision is unchanged).
//! And the recorded fields are STRUCTURALLY safe: the trace input builders
//! ([`ironauth_store::PolicyDecisionInputs`]) accept only typed safe fields (an acr value,
//! a signal name and level, a connector slug, a bounded failure kind), so no claim value,
//! token, or secret is representable, let alone recorded. The redaction corpus CI gate
//! (`scripts/diagnostics-redaction-scan.sh`) proves it.

use ironauth_config::DiagnosticVerbosity;
use ironauth_store::{
    NewPolicyDecisionTrace, NewTokenSizeEvent, PolicyDecisionInputs, PolicyKind, PolicyOutcome,
    PolicyTraceSignal, Scope, TokenSizeKind, UserId,
};

use crate::risk::{RiskAction, RiskDecision};
use crate::state::OidcState;
use crate::step_up::{AuthnRequirement, Satisfaction};

/// The serialized ID token byte size beyond which a mint is recorded as a token size
/// (claim bloat) event (issue #91). A lean ID token is well under this; a token that
/// crosses it carries an unusual amount of claims, which the M9 warnings read surfaces
/// so an operator can see a claim mapping or a scope set inflating the token. It is a
/// growth signal, never a limit: the token is minted and returned unchanged regardless.
const ID_TOKEN_BLOAT_THRESHOLD_BYTES: usize = 3072;

/// The bounded outcome of a claim mapping evaluation, for the trace (issue #91). Either
/// the mapping resolved (with the number of traits it produced) or it failed closed
/// (with a bounded, non secret failure kind, never a claim value or a claim path).
#[derive(Debug, Clone, Copy)]
pub(crate) enum ClaimMappingTraceOutcome {
    /// The mapping resolved, producing this many traits.
    Resolved { trait_count: u32 },
    /// The mapping failed closed with this bounded failure kind.
    Failed { kind: &'static str },
}

/// Record one policy decision trace, best effort and verbosity gated. A failure to
/// record is logged and swallowed: the trace is a side channel for operators, never a
/// gate on the decision. At `off` verbosity this is a no op.
async fn record(state: &OidcState, scope: Scope, trace: NewPolicyDecisionTrace) {
    if state.diagnostics_verbosity() == DiagnosticVerbosity::Off {
        return;
    }
    if let Err(error) = state
        .store()
        .scoped(scope)
        .policy_decision_traces()
        .record(state.env(), state.diagnostic_retention_micros(), &trace)
        .await
    {
        tracing::warn!(%error, "could not record a policy decision trace");
    }
}

/// Record a STEP UP requirement evaluation as a trace (issue #91), best effort. The
/// caller passes exactly what it fed [`crate::step_up::evaluate`] plus the outcome, so
/// the trace mirrors the decision the live path made WITHOUT re running or altering it.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn record_step_up_trace(
    state: &OidcState,
    scope: Scope,
    subject: Option<&str>,
    requirement: &AuthnRequirement,
    achieved_acr: &str,
    auth_time_micros: Option<i64>,
    now_micros: i64,
    satisfaction: Satisfaction,
) {
    // The derived age of the authentication in seconds, when it could be established.
    let auth_age_secs = auth_time_micros.map(|auth| now_micros.saturating_sub(auth) / 1_000_000);
    let (outcome, reason, acr_unmet, age_lapsed) = match satisfaction {
        Satisfaction::Satisfied => (PolicyOutcome::Satisfied, None, false, false),
        Satisfaction::NeedsStepUp {
            acr_unmet,
            age_lapsed,
        } => {
            let reason = match (acr_unmet, age_lapsed) {
                (true, true) => "acr_unmet,age_lapsed",
                (true, false) => "acr_unmet",
                (false, true) => "age_lapsed",
                // evaluate() only returns NeedsStepUp when at least one flag is set.
                (false, false) => "step_up_required",
            };
            (
                PolicyOutcome::StepUpRequired,
                Some(reason.to_owned()),
                acr_unmet,
                age_lapsed,
            )
        }
    };
    let inputs = PolicyDecisionInputs::StepUp {
        required_acr: requirement.min_acr.clone(),
        achieved_acr: achieved_acr.to_owned(),
        max_auth_age_secs: requirement.max_auth_age_secs,
        auth_age_secs,
        acr_unmet,
        age_lapsed,
    };
    record(
        state,
        scope,
        NewPolicyDecisionTrace {
            policy: PolicyKind::StepUp,
            subject: subject.map(str::to_owned),
            outcome,
            reason,
            inputs,
        },
    )
    .await;
}

/// Record a RISK scoring decision as a trace (issue #91), best effort. The risk decision
/// is already persisted to `risk_decisions`; this ALSO records it as a policy trace so it
/// appears alongside the step up and claim mapping decisions in the M9 inspector, with the
/// same safe field projection (the signal NAMES and levels, never the raw IP or counts).
pub(crate) async fn record_risk_trace(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
    decision: &RiskDecision,
) {
    let (outcome, reason) = match decision.action {
        RiskAction::Allow => (PolicyOutcome::Satisfied, "allow"),
        RiskAction::Notify => (PolicyOutcome::Satisfied, "notify"),
        RiskAction::Challenge => (PolicyOutcome::StepUpRequired, "challenge"),
        RiskAction::Block => (PolicyOutcome::Deny, "block"),
    };
    let signals = decision
        .outcomes
        .iter()
        .map(|signal| PolicyTraceSignal {
            name: signal.name.to_owned(),
            level: signal.level.as_str().to_owned(),
        })
        .collect();
    let inputs = PolicyDecisionInputs::Risk {
        level: decision.level.as_str().to_owned(),
        signals,
    };
    record(
        state,
        scope,
        NewPolicyDecisionTrace {
            policy: PolicyKind::Risk,
            subject: Some(subject.to_string()),
            outcome,
            reason: Some(reason.to_owned()),
            inputs,
        },
    )
    .await;
}

/// Record a CLAIM MAPPING evaluation as a trace (issue #91), best effort. The subject is
/// deliberately absent: the mapping runs BEFORE the local user is provisioned, and the
/// upstream subject is never recorded (the connector slug identifies the decision). The
/// failure kind is a bounded, non secret hint, never a claim value or a claim path.
pub(crate) async fn record_claim_mapping_trace(
    state: &OidcState,
    scope: Scope,
    connector: &str,
    outcome: ClaimMappingTraceOutcome,
) {
    let (policy_outcome, reason, mapped_trait_count, failure_kind) = match outcome {
        ClaimMappingTraceOutcome::Resolved { trait_count } => {
            (PolicyOutcome::Satisfied, None, Some(trait_count), None)
        }
        ClaimMappingTraceOutcome::Failed { kind } => (
            PolicyOutcome::Deny,
            Some(kind.to_owned()),
            None,
            Some(kind.to_owned()),
        ),
    };
    let inputs = PolicyDecisionInputs::ClaimMapping {
        connector: connector.to_owned(),
        mapped_trait_count,
        failure_kind,
    };
    record(
        state,
        scope,
        NewPolicyDecisionTrace {
            policy: PolicyKind::ClaimMapping,
            subject: None,
            outcome: policy_outcome,
            reason,
            inputs,
        },
    )
    .await;
}

/// Record a TOKEN SIZE (claim bloat) event for a minted ID token (issue #91), best
/// effort and verbosity gated. Only a token whose serialized byte size EXCEEDS the bloat
/// threshold is recorded, so the sink holds only actual bloat events (a lean token writes
/// nothing). The token itself is NEVER recorded: only its byte size and (best effort)
/// claim count, both bounded integers, plus the non secret client id. The token is minted
/// and returned unchanged regardless of this capture.
pub(crate) async fn record_token_size_event(
    state: &OidcState,
    scope: Scope,
    client_id: &str,
    id_token: &str,
) {
    if state.diagnostics_verbosity() == DiagnosticVerbosity::Off {
        return;
    }
    let byte_size = id_token.len();
    if byte_size <= ID_TOKEN_BLOAT_THRESHOLD_BYTES {
        return;
    }
    // The claim count is a best effort read of our OWN freshly minted, unverified token's
    // payload: a bounded integer, never a claim value. Any decode hiccup yields no count.
    let claim_count = id_token_claim_count(id_token).and_then(|count| i64::try_from(count).ok());
    let byte_size = i64::try_from(byte_size).unwrap_or(i64::MAX);
    if let Err(error) = state
        .store()
        .scoped(scope)
        .token_size_events()
        .record(
            state.env(),
            state.diagnostic_retention_micros(),
            NewTokenSizeEvent {
                token_type: TokenSizeKind::IdToken,
                byte_size,
                claim_count,
                client_id,
            },
        )
        .await
    {
        tracing::warn!(%error, "could not record a token size event");
    }
}

/// The number of top level claims in a compact JWS ID token's payload, best effort. Reads
/// only the COUNT of the payload object's keys (never a value), from our own freshly minted
/// token. Returns [`None`] for any structural problem (not a JWS, bad base64, not an
/// object): the caller then records no claim count, an inert, truthful absence.
fn id_token_claim_count(id_token: &str) -> Option<usize> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let payload = id_token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    value.as_object().map(serde_json::Map::len)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The redaction corpus for the policy trace and token size record types (issue #91),
    /// the sibling of the client auth diagnostics corpus. It stuffs known secret / token /
    /// claim value sentinels into EVERY field the safe field builders accept, serializes
    /// every resulting record, and asserts NO sentinel appears anywhere. The guarantee is
    /// structural first: the builders accept only typed safe fields (an acr, a signal name
    /// and level, a connector slug, a bounded failure kind, a byte size, a client id), so a
    /// claim value has NOWHERE to go. This is the CI belt and suspenders. The shell wrapper
    /// is `scripts/diagnostics-redaction-scan.sh`.
    #[test]
    fn redaction_corpus_leaks_no_secret_sentinel() {
        use std::fmt::Write as _;

        // Distinct sentinels, one per class of material a hostile decision could carry.
        const SENTINELS: &[&str] = &[
            "SUPERSECRETCLAIMVALUESENTINEL",
            "OVERSIZEDBEARERTOKENSENTINEL",
            "UPSTREAMSUBJECTPIISENTINEL",
        ];

        let mut serialized = String::new();

        // A step up trace built from server vocabulary acr values (never a claim value).
        let step_up = NewPolicyDecisionTrace {
            policy: PolicyKind::StepUp,
            // The subject is a usr_ handle (a blind reference); the sentinel here has
            // nowhere to become a claim value.
            subject: Some("usr_safehandle".to_owned()),
            outcome: PolicyOutcome::StepUpRequired,
            reason: Some("acr_unmet".to_owned()),
            inputs: PolicyDecisionInputs::StepUp {
                required_acr: Some("urn:ironauth:acr:mfa".to_owned()),
                achieved_acr: "urn:ironauth:acr:pwd".to_owned(),
                max_auth_age_secs: Some(300),
                auth_age_secs: Some(42),
                acr_unmet: true,
                age_lapsed: false,
            },
        };
        write!(serialized, "{step_up:?}{}", step_up.inputs.to_json()).expect("write");

        // A risk trace built from signal NAMES and levels (never the raw IP or counts).
        let risk = NewPolicyDecisionTrace {
            policy: PolicyKind::Risk,
            subject: Some("usr_safehandle".to_owned()),
            outcome: PolicyOutcome::Deny,
            reason: Some("block".to_owned()),
            inputs: PolicyDecisionInputs::Risk {
                level: "high".to_owned(),
                signals: vec![
                    PolicyTraceSignal {
                        name: "new_device".to_owned(),
                        level: "med".to_owned(),
                    },
                    PolicyTraceSignal {
                        name: "velocity".to_owned(),
                        level: "high".to_owned(),
                    },
                ],
            },
        };
        write!(serialized, "{risk:?}{}", risk.inputs.to_json()).expect("write");

        // A claim mapping trace: the connector slug and a bounded failure kind only.
        let mapping = NewPolicyDecisionTrace {
            policy: PolicyKind::ClaimMapping,
            subject: None,
            outcome: PolicyOutcome::Deny,
            reason: Some("missing_required_claim".to_owned()),
            inputs: PolicyDecisionInputs::ClaimMapping {
                connector: "octa".to_owned(),
                mapped_trait_count: None,
                failure_kind: Some("missing_required_claim".to_owned()),
            },
        };
        write!(serialized, "{mapping:?}{}", mapping.inputs.to_json()).expect("write");

        // A token size event: a byte size and claim count (integers) plus the client id.
        let token_size = NewTokenSizeEvent {
            token_type: TokenSizeKind::IdToken,
            byte_size: 4096,
            claim_count: Some(37),
            client_id: "cli_safe",
        };
        write!(serialized, "{token_size:?}").expect("write");

        // Positive control: a SAFE field DID make it through (the projection is real).
        assert!(
            serialized.contains("urn:ironauth:acr:mfa") && serialized.contains("new_device"),
            "the safe fields must be recorded (the projection is real)"
        );

        // The GUARANTEE: no secret sentinel appears anywhere in any serialization. None of
        // the sentinels is representable, because no field accepts a claim value.
        for sentinel in SENTINELS {
            assert!(
                !serialized.contains(sentinel),
                "a secret sentinel leaked into a policy trace or token size record: {sentinel}"
            );
        }
    }
}
