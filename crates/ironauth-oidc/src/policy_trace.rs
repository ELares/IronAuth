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
//!
//! With EXACTLY ONE exception, which is deliberate and is documented at the site it
//! applies to: [`record_permission_budget_event`] (issue #98) is NOT verbosity gated,
//! because issue #98's covenant is that no configuration can produce a silent permission
//! drop and the gate would make `diagnostics.verbosity = "off"` exactly that
//! configuration. Read that function's doc comment before concluding the missing gate is
//! a bug.
//!
//! And the recorded fields are STRUCTURALLY safe: the trace input builders
//! ([`ironauth_store::PolicyDecisionInputs`]) accept only typed safe fields (an acr value,
//! a signal name and level, a connector slug, a bounded failure kind), so no claim value,
//! token, or secret is representable, let alone recorded. The redaction corpus CI gate
//! (`scripts/diagnostics-redaction-scan.sh`) proves it.

use ironauth_config::DiagnosticVerbosity;
use ironauth_store::{
    NewPolicyDecisionTrace, NewTokenSizeEvent, PolicyDecisionInputs, PolicyKind, PolicyOutcome,
    PolicyTraceSignal, Scope, TokenSizeKind, TokenSizeReason, UserId,
};

use crate::permission_budget::PermissionStatus;
use crate::risk::{RiskAction, RiskDecision};
use crate::state::OidcState;
use crate::step_up::{AuthnRequirement, Satisfaction};

/// The serialized ID token byte size beyond which a mint is recorded as a token size
/// (claim bloat) event (issue #91). A lean ID token is well under this; a token that
/// crosses it carries an unusual amount of claims, which the M9 warnings read surfaces
/// so an operator can see a claim mapping or a scope set inflating the token. It is a
/// growth signal, never a limit: the token is minted and returned unchanged regardless.
///
/// PUBLIC so the parity with the access-token budget's shipped approach threshold
/// (`ironauth_config::TOKEN_CLAIMS_DEFAULT_ACCESS_TOKEN_WARN_BYTES`, issue #98) can be
/// asserted from the one crate that can see both. The two numbers are deliberately
/// EQUAL so an operator meets ONE number across both token kinds rather than two that
/// mean the same thing and can disagree; the assertion lives in
/// `ironauth-admin`'s `error` test module, beside the session-TTL and group-depth
/// ceiling agreements. Moving either number alone turns it red.
pub const ID_TOKEN_BLOAT_THRESHOLD_BYTES: usize = 3072;

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
                // The issue #98 budget dimensions are absent on a bloat event: an ID token
                // has no permission budget, so NULL here reads as "not a budget event",
                // which is exactly how the warnings read separates the two kinds.
                reason: None,
                audience: None,
                organization_id: None,
                permission_count: None,
                permission_status: None,
            },
        )
        .await
    {
        tracing::warn!(%error, "could not record a token size event");
    }
}

/// The permission-claim budget verdict for one issuance, as it is RECORDED (issue #98).
///
/// Every field is bounded and non secret, and there is deliberately no field for the
/// permission SLUGS: a count answers the operator's question and a list would grow an
/// append-only row without bound. The redaction corpus below carries the argument for
/// each field, and it is precise about which kind of guarantee each rests on: three of
/// them are structurally incapable of holding a sentinel (two enums and an integer),
/// while `audience` and `organization_id` are `&str` and would record one verbatim, so
/// their guarantee is about the CALLER and the corpus routes a real sentinel through both
/// to prove it can see them.
///
/// `organization_id` is NOT optional here, unlike the column behind it. A permission
/// claim exists only in an organization context, so a budget verdict without one is not a
/// thing this type should be able to express; the column is nullable because the ID-token
/// bloat event that shares the sink has none.
///
/// `audience` IS optional, and that is the one place this type is looser than the reader
/// of these docs might expect. The budget produces ONE verdict for the whole TOKEN, and a
/// token may target several resource servers ([`crate::AccessTokenTarget::audiences`] is a
/// `Vec`, per RFC 8707 and RFC 9068). A verdict is therefore attributable to a single
/// audience only when the token targets exactly one; on a multi-audience token the mint
/// passes [`None`] rather than picking one and mislabelling the verdict as belonging to
/// it, and the warnings read renders the organization alone.
///
/// LIVE: constructed by `crate::token::record_budget_outcome`, from both mint hooks
/// (issue #98, PR 13).
#[derive(Debug, Clone, Copy)]
pub(crate) struct PermissionBudgetEvent<'a> {
    /// WHY the verdict was recorded: approaching the budget, or which withholding.
    pub reason: TokenSizeReason,
    /// The compact access token size in bytes the verdict was reached about.
    pub token_bytes: usize,
    /// How many permissions the resolved set held.
    pub permission_count: usize,
    /// The resource server audience the access token was minted for: an
    /// operator-registered URI. [`None`] when the token targets SEVERAL resource servers,
    /// because one verdict cannot be attributed to one of them.
    pub audience: Option<&'a str>,
    /// The organization whose resolved permission set the verdict is about: a scoped
    /// `org_` identifier.
    pub organization_id: &'a str,
    /// The `permissions_status` the token PUT ON THE WIRE, when it put one there.
    ///
    /// [`None`] for [`TokenSizeReason::BudgetApproaching`], where nothing was withheld and
    /// the token therefore carries no status. Recorded because it is what tells a resource
    /// server whether to fall back to `roles` (`budget_exceeded`) or to consult a policy
    /// decision point (`pdp_required`), and an event that could not express it would be a
    /// record of a withholding missing what the token said about the withholding.
    pub permission_status: Option<PermissionStatus>,
}

/// Record a PERMISSION-CLAIM BUDGET event (issue #98) into the same sink
/// [`record_token_size_event`] writes, as an `access_token` row carrying the five
/// migration 0095 budget dimensions.
///
/// # The verbosity gate is DELIBERATELY ABSENT
///
/// UNLIKE every other recorder in this module this one is NOT gated on
/// [`DiagnosticVerbosity`], and the exemption is the whole point rather than an
/// oversight. Issue #98 requires that no configuration can produce a silent permission
/// drop; routing this through the verbosity gate would make
/// `diagnostics.verbosity = "off"` exactly that configuration. A reviewer who knows this
/// module will read the missing gate as a bug, so it is stated here: the gate is
/// deliberately absent. `no_configuration_silences_the_permission_budget_event` drives
/// this function at EVERY verbosity setting, `off` included, and asserts a row every
/// time; its sibling asserts [`record_token_size_event`] at `off` writes nothing, so the
/// two behaviours are pinned apart rather than assumed apart.
///
/// The exemption is from VERBOSITY only. `diagnostics.retention_secs` still applies (it
/// is threaded into the sink's on-insert prune exactly as for a bloat event), which is
/// the next paragraph's subject.
///
/// # This row is a CONVENIENCE view, never the record of record
///
/// The sink is retention pruned and its read is clamped to 200 rows
/// (`TokenSizeEventsRepo::MAX_QUERY_LIMIT`), so an operator can lose these rows to time
/// or to volume. That is acceptable ONLY because the token itself carries
/// `permissions_status`: the durable record of a withholding is
/// the WIRE CONTRACT, and this row is the operator's convenience view of it. If this
/// event were the sole record of a withholding, retention pruning would silently defeat
/// the covenant above, and the verbosity exemption would not save it.
///
/// The retention half of that bound is MEASURED, twice and through different seams:
/// `a_recorded_budget_event_is_retention_pruned` (`ironauth-store`'s repository tests)
/// drives the repository directly with a literal window, and
/// `the_recorder_threads_the_configured_retention` below drives THIS function with a real
/// [`ironauth_config::DiagnosticsConfig`], which is what pins the threading rather than the
/// store call. The 200-row half is not a measurement at all: it is the constant named
/// above, applied per event family by `TokenSizeEventsRepo::recent_by_kind` so that one
/// family cannot evict the other.
///
/// The sharpest retention case is worth stating outright rather than leaving to be
/// derived. `diagnostics.retention_secs = 0` is a valid, safe posture, and at 0 every row
/// expires the instant it is written, so each insert prunes its predecessor and this sink
/// holds AT MOST ONE budget row per scope. An operator who sets 0 still keeps the covenant
/// (the token carries `permissions_status`) and keeps essentially none of the convenience
/// view. That is the intended reading of 0, not a bug in this recorder.
///
/// That is also why this recorder stays BEST EFFORT in the shape the rest of the module
/// is: a write failure is logged and swallowed and the token is minted and returned
/// unchanged. Failing the mint to protect an advisory row would trade an availability
/// outage for a convenience view, and the covenant does not depend on this write landing.
///
/// The claim count is deliberately [`None`]: the number that matters for a budget verdict
/// is the permission count, which is recorded, and decoding our own freshly minted access
/// token to count its top-level claims would buy nothing here.
///
/// This is the FIRST construction of [`TokenSizeKind::AccessToken`] in the product. The
/// variant and the `token_type` CHECK that admits `'access_token'` have both existed
/// since migration 0073 (issue #91) with nothing ever writing the value, so a
/// permission-budget event is the first access-token size event IronAuth has recorded.
///
/// LIVE on both mint hooks (issue #98, PR 13), through the one
/// `crate::token::record_budget_outcome` that decides which verdicts are worth a row.
pub(crate) async fn record_permission_budget_event(
    state: &OidcState,
    scope: Scope,
    client_id: &str,
    event: PermissionBudgetEvent<'_>,
) {
    let byte_size = i64::try_from(event.token_bytes).unwrap_or(i64::MAX);
    let permission_count = i64::try_from(event.permission_count).unwrap_or(i64::MAX);
    if let Err(error) = state
        .store()
        .scoped(scope)
        .token_size_events()
        .record(
            state.env(),
            state.diagnostic_retention_micros(),
            NewTokenSizeEvent {
                token_type: TokenSizeKind::AccessToken,
                byte_size,
                claim_count: None,
                client_id,
                reason: Some(event.reason),
                audience: event.audience,
                organization_id: Some(event.organization_id),
                permission_count: Some(permission_count),
                permission_status: event.permission_status.map(PermissionStatus::as_str),
            },
        )
        .await
    {
        tracing::warn!(%error, "could not record a permission budget event");
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

    /// Distinct sentinels, one per class of material a hostile decision could carry.
    /// Module scoped so the corpus and the two probes that prove the scan is not vacuous
    /// all use the SAME strings.
    const SENTINELS: &[&str] = &[
        "SUPERSECRETCLAIMVALUESENTINEL",
        "OVERSIZEDBEARERTOKENSENTINEL",
        "UPSTREAMSUBJECTPIISENTINEL",
    ];

    /// The corpus's guarantee as a reusable check: panic naming the sentinel that leaked.
    ///
    /// A function rather than a loop inlined in the test, because that is what lets the two
    /// `should_panic` probes below drive the SAME scan over a deliberately leaky corpus. A
    /// scan that only ever runs over material that cannot leak asserts nothing; these
    /// probes are what make deleting this loop a test failure rather than a silent no-op.
    fn assert_no_sentinel_leaked(serialized: &str) {
        for sentinel in SENTINELS {
            assert!(
                !serialized.contains(sentinel),
                "a secret sentinel leaked into a policy trace or token size record: {sentinel}"
            );
        }
    }

    /// The redaction corpus for the policy trace and token size record types (issue #91),
    /// the sibling of the client auth diagnostics corpus. It builds every record shape the
    /// safe field builders accept, serializes each, and asserts NO sentinel appears
    /// anywhere. The guarantee is structural first: the builders accept only typed safe
    /// fields (an acr, a signal name and level, a connector slug, a bounded failure kind, a
    /// byte size, a client id), so a claim value has NOWHERE to go. This is the CI belt and
    /// suspenders. The shell wrapper is `scripts/diagnostics-redaction-scan.sh`.
    ///
    /// Issue #98 adds the five PERMISSION-BUDGET dimensions to the token size record, and
    /// the corpus carries the argument for each in prose at the site rather than leaving it
    /// to be assumed. Three of the five are structurally safe (two closed enums and an
    /// integer) and two are free-form strings whose safety is a property of the CALLER, and
    /// that difference is spelled out below rather than blurred. The two `should_panic`
    /// probes beside this test prove the scan can actually SEE the free-form two, and
    /// `the_closed_budget_vocabularies_cannot_express_a_sentinel` proves the other three
    /// have nowhere to put one.
    #[test]
    fn redaction_corpus_leaks_no_secret_sentinel() {
        use std::fmt::Write as _;

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

        // Both TOKEN SIZE record shapes, serialized by the helper below (which carries the
        // per field argument for the issue #98 dimensions beside the record it is about).
        serialized.push_str(&token_size_records_serialization());

        // Positive control: a SAFE field DID make it through (the projection is real).
        assert!(
            serialized.contains("urn:ironauth:acr:mfa") && serialized.contains("new_device"),
            "the safe fields must be recorded (the projection is real)"
        );

        // The GUARANTEE: no secret sentinel appears anywhere in any serialization.
        assert_no_sentinel_leaked(&serialized);
    }

    /// The token size half of the corpus above: the issue #91 ID-token BLOAT event and the
    /// issue #98 PERMISSION BUDGET event, serialized, for the caller to scan for sentinels.
    ///
    /// Split out of the test rather than suppressed with an `allow`, because the argument
    /// for the five budget dimensions belongs beside the record it is about and it is long
    /// enough to push one function past the line budget on its own.
    fn token_size_records_serialization() -> String {
        use std::fmt::Write as _;

        let mut serialized = String::new();

        // A token size event: a byte size and claim count (integers) plus the client id.
        let token_size = NewTokenSizeEvent {
            token_type: TokenSizeKind::IdToken,
            byte_size: 4096,
            claim_count: Some(37),
            client_id: "cli_safe",
            reason: None,
            audience: None,
            organization_id: None,
            permission_count: None,
            permission_status: None,
        };
        write!(serialized, "{token_size:?}").expect("write");

        serialized.push_str(&budget_record_serialization(
            "https://api.example.com/orders",
            "org_safehandle",
        ));
        serialized
    }

    /// One PERMISSION BUDGET record (issue #98), serialized, with the two FREE-FORM fields
    /// supplied by the caller.
    ///
    /// They are parameters and not literals for one reason: it is what lets the
    /// `should_panic` probes route a real sentinel through `audience` and through
    /// `organization_id` and watch the corpus scan catch it. A corpus that only ever holds
    /// safe values cannot tell a working scan from a deleted one.
    ///
    /// Each of the five dimensions is argued rather than assumed, because this is exactly
    /// the kind of claim that reads as obvious and is not.
    ///
    ///   * `reason` is SERVER VOCABULARY: it comes from the closed `TokenSizeReason` enum,
    ///     so the only strings this field can ever hold are the four spelled in that
    ///     enum's `as_str`. A hostile input cannot reach it at all, in the same way a
    ///     hostile input cannot reach the bounded `failure_kind` above.
    ///   * `permission_status` is server vocabulary of the same shape: the closed
    ///     `PermissionStatus` enum, whose whole value space is `budget_exceeded` and
    ///     `pdp_required`.
    ///   * `permission_count` is a bounded integer, of the same class as `byte_size` and
    ///     `claim_count`. It is the only reason the permission SLUGS are absent from this
    ///     record: a count answers the operator's question ("how far past the budget"), so
    ///     the list is unnecessary, and being unnecessary it is not representable. A slug
    ///     would in fact be safe by the acr-value argument (it is server vocabulary an
    ///     operator typed into the permission table, not a claim value), which is precisely
    ///     why the argument has to be written down: the reason there is no slug field is
    ///     UNBOUNDED GROWTH on an append-only row, not secrecy, and a future reader must
    ///     not "fix" the wrong problem by adding one.
    ///   * `audience` is an OPERATOR-REGISTERED resource server URI: the same string
    ///     `resource_servers.audience` holds and the same string the token's own `aud`
    ///     claim carries to the resource server. It is a NAME the operator chose for an API
    ///     they own, never a subject, never a credential, and never derived from an end
    ///     user's upstream claims. It is not a secret for the same reason `aud` is not: the
    ///     party it is shown to is the party that already knows it.
    ///   * `organization_id` is a scoped `org_` identifier: a BLIND REFERENCE, of the same
    ///     class as the `usr_` handle the step-up trace above records. It names a row and
    ///     carries no attribute of that row, so an operator who reads it learns nothing
    ///     they could not already read from the organization record under the same scope
    ///     key.
    ///
    /// Be precise about WHICH KIND of guarantee each rests on, because they are not the
    /// same kind and treating them as one is how a leak gets waved through. The first
    /// three are STRUCTURAL: two enums and an integer, so no sentinel is representable in
    /// them at all, exactly like `byte_size`. The last two are `&str`, so a sentinel placed
    /// in them WOULD be recorded verbatim, and pretending otherwise would be false. Their
    /// guarantee is that nothing hostile reaches them: both are resolved on the mint path
    /// from the operator's own configuration (the `resource_servers` row the audience
    /// selects) and from the organization frozen onto the grant, neither of which is read
    /// from an end user's claims, from a token, or from a secret.
    ///
    /// That is CALLER DISCIPLINE, not a property of the type, and nothing in this file
    /// enforces it. What forces a future field to be thought about is the struct literal
    /// below failing to compile until it is given a value; that is a decision point, not a
    /// guarantee, and it is the honest thing to promise.
    fn budget_record_serialization(audience: &str, organization_id: &str) -> String {
        use std::fmt::Write as _;

        let mut serialized = String::new();
        let budget = NewTokenSizeEvent {
            token_type: TokenSizeKind::AccessToken,
            byte_size: 8192,
            claim_count: None,
            client_id: "cli_safe",
            reason: Some(TokenSizeReason::BudgetOverflowBytes),
            audience: Some(audience),
            organization_id: Some(organization_id),
            permission_count: Some(412),
            permission_status: Some(PermissionStatus::BudgetExceeded.as_str()),
        };
        // Both spellings of the reason are scanned: Debug prints the RUST variant name,
        // while the value that reaches the column is `as_str`, and the corpus must cover the
        // string that is actually written rather than only the one Debug happens to show.
        write!(
            serialized,
            "{budget:?}{}",
            budget
                .reason
                .map(TokenSizeReason::as_str)
                .unwrap_or_default()
        )
        .expect("write");

        // Positive control for the issue #98 dimensions specifically: all five DID make it
        // into the serialization, so the caller's sentinel scan is running over them rather
        // than over a record that silently dropped them.
        assert!(
            serialized.contains("budget_overflow_bytes")
                && serialized.contains("BudgetOverflowBytes")
                && serialized.contains(audience)
                && serialized.contains(organization_id)
                && serialized.contains("412")
                && serialized.contains("budget_exceeded"),
            "the five permission budget dimensions must be recorded (the projection is real)"
        );

        serialized
    }

    /// The corpus scan CAN see the `audience` field: a sentinel routed through it comes out
    /// the other side and the scan fires (issue #98).
    ///
    /// This is what stops the negative half of the corpus being vacuous for this field. It
    /// is deliberately NOT a claim that a sentinel cannot reach `audience`, because it can:
    /// the field is a `&str`. It is the weaker, TRUE claim that if one ever did, the corpus
    /// would say so.
    #[test]
    #[should_panic(expected = "a secret sentinel leaked")]
    fn the_sentinel_scan_catches_a_leak_through_the_audience() {
        assert_no_sentinel_leaked(&budget_record_serialization(SENTINELS[1], "org_safehandle"));
    }

    /// The same probe for `organization_id`, the other free-form budget field. Separate
    /// tests rather than one, so a scan that saw only one of the two would still fail.
    #[test]
    #[should_panic(expected = "a secret sentinel leaked")]
    fn the_sentinel_scan_catches_a_leak_through_the_organization() {
        assert_no_sentinel_leaked(&budget_record_serialization(
            "https://api.example.com/orders",
            SENTINELS[2],
        ));
    }

    /// The other three budget dimensions have NOWHERE to put a sentinel, and that is proved
    /// by enumeration rather than asserted (issue #98).
    ///
    /// `reason` and `permission_status` are closed enums, so their entire value space is
    /// the two lists below and this sweep is total over it; `permission_count` is an `i64`,
    /// whose whole value space is digits and a sign. A guarantee about a finite value space
    /// is the one kind of "cannot happen" a test can actually establish, which is why the
    /// free-form pair get probes instead.
    #[test]
    fn the_closed_budget_vocabularies_cannot_express_a_sentinel() {
        for reason in EVERY_REASON {
            assert_no_sentinel_leaked(reason.as_str());
        }
        for status in [
            PermissionStatus::BudgetExceeded,
            PermissionStatus::PdpRequired,
        ] {
            assert_no_sentinel_leaked(status.as_str());
        }
        // The integer dimension: every value it can hold renders as digits, so a sentinel
        // is not representable. `i64::MIN` and `i64::MAX` are the extremes of that space.
        for count in [i64::MIN, -1, 0, 412, i64::MAX] {
            let rendered = count.to_string();
            assert!(
                rendered
                    .chars()
                    .all(|character| character.is_ascii_digit() || character == '-'),
                "a permission count renders as digits only: {rendered}"
            );
        }
    }

    /// Every [`TokenSizeReason`], exhaustively. `every_reason_is_listed` is what keeps this
    /// total: a variant added to the enum stops compiling there rather than quietly
    /// escaping the sweeps that iterate this.
    const EVERY_REASON: &[TokenSizeReason] = &[
        TokenSizeReason::BudgetApproaching,
        TokenSizeReason::BudgetOverflowCount,
        TokenSizeReason::BudgetOverflowBytes,
        TokenSizeReason::RolesOnlyStillOversize,
    ];

    /// The exhaustiveness pin for [`EVERY_REASON`]: the `match` is total, so a new variant
    /// is a compile error here, and the index it maps to must be the slot the list holds.
    #[test]
    fn every_reason_is_listed() {
        for reason in EVERY_REASON {
            let slot = match reason {
                TokenSizeReason::BudgetApproaching => 0,
                TokenSizeReason::BudgetOverflowCount => 1,
                TokenSizeReason::BudgetOverflowBytes => 2,
                TokenSizeReason::RolesOnlyStillOversize => 3,
            };
            assert_eq!(
                EVERY_REASON[slot], *reason,
                "EVERY_REASON must list every variant, in the order the match spells"
            );
        }
        assert_eq!(EVERY_REASON.len(), 4, "and hold nothing else");
    }

    /// The closed reason vocabulary round-trips through its own wire strings (issue #98),
    /// over the FULL variant list, so the read side's `from_wire` can never drift from the
    /// write side's `as_str`. A variant added without a `from_wire` arm turns this red.
    #[test]
    fn the_permission_budget_reason_vocabulary_round_trips() {
        for reason in EVERY_REASON {
            assert_eq!(
                TokenSizeReason::from_wire(reason.as_str()),
                Some(*reason),
                "the recorded wire string must parse back to the same reason"
            );
        }
        assert_eq!(
            TokenSizeReason::from_wire("some_future_reason"),
            None,
            "an unknown reason parses to None so an advisory read skips it"
        );
    }
}

/// The DB-backed half of the issue #98 covenant: no configuration silences a permission
/// budget event.
///
/// Separate from the module's other tests and behind the `testing` feature because it
/// needs a real Postgres (`scripts/with-test-db.sh`), while the redaction corpus above is
/// database-free so `scripts/diagnostics-redaction-scan.sh` can run it in any lane. It
/// lives in the library rather than in `tests/` because the two recorders under
/// comparison are `pub(crate)` and must stay that way: they have exactly one intended
/// caller each (the mint), and widening them to `pub` to make them testable would put an
/// internal recorder in the crate's public API.
#[cfg(all(test, feature = "testing"))]
mod exemption_tests {
    use super::{PermissionBudgetEvent, record_permission_budget_event, record_token_size_event};
    use crate::issuer::{IssuerRegistry, JwksCacheWindow};
    use crate::permission_budget::PermissionStatus;
    use crate::state::OidcState;
    use ironauth_config::{DiagnosticVerbosity, DiagnosticsConfig, OidcConfig};
    use ironauth_env::Env;
    use ironauth_store::test_support::TestDatabase;
    use ironauth_store::{Scope, TokenSizeEventRecord, TokenSizeKind, TokenSizeReason};
    use std::sync::Arc;
    use std::time::{Duration, UNIX_EPOCH};

    /// Every verbosity setting the operator can choose, taken from the enum's OWN list
    /// rather than written out again here.
    ///
    /// Two mechanisms keep a fourth setting from silently escaping this loop, and they
    /// catch different things. Being derived from [`DiagnosticVerbosity::ALL`] is what
    /// puts a new setting IN the list (that list's own completeness is measured in
    /// `ironauth-config`, against the variant list `schemars` derives from the enum).
    /// The exhaustive `match` inside the loop below is what makes a new setting a
    /// COMPILE error here until someone looks at it. A literal written out here had
    /// neither property: the `match` alone would have been satisfied by adding an arm,
    /// leaving the list one setting short and this test quietly narrower.
    const EVERY_VERBOSITY: &[DiagnosticVerbosity] = &DiagnosticVerbosity::ALL;

    /// A store-backed [`OidcState`] at `verbosity`, and the scope its writes land in.
    ///
    /// No signing key is provisioned: neither recorder signs, mints, or reads a key, so
    /// the seeded scope is all either needs.
    async fn state_at(
        db: &TestDatabase,
        env: &Env,
        verbosity: DiagnosticVerbosity,
    ) -> (OidcState, Scope) {
        state_configured(
            db,
            env,
            &DiagnosticsConfig {
                verbosity,
                ..DiagnosticsConfig::default()
            },
        )
        .await
    }

    /// A store-backed [`OidcState`] under a WHOLE [`DiagnosticsConfig`], and the scope its
    /// writes land in. The retention test needs to set `retention_secs`, not just the
    /// verbosity, and it has to go through the real config type so the recorder's threading
    /// of `diagnostics.retention_secs` is what is under test rather than a store constant.
    async fn state_configured(
        db: &TestDatabase,
        env: &Env,
        diagnostics: &DiagnosticsConfig,
    ) -> (OidcState, Scope) {
        let scope = db.seed_scope(env).await;
        let registry = Arc::new(IssuerRegistry::store_backed(
            "https://issuer.test",
            JwksCacheWindow::default(),
            db.store().clone(),
        ));
        let state = OidcState::new(
            db.store().clone(),
            env.clone(),
            registry,
            &OidcConfig::default(),
            "https://issuer.test",
        )
        .with_diagnostics(diagnostics);
        (state, scope)
    }

    /// Read every event row in `scope`, newest first.
    async fn events_in(state: &OidcState, scope: Scope) -> Vec<TokenSizeEventRecord> {
        state
            .store()
            .scoped(scope)
            .token_size_events()
            .recent(50)
            .await
            .expect("read the recorded events")
    }

    /// A budget event whose five dimensions are all distinguishable from a default.
    fn sample_event(reason: TokenSizeReason) -> PermissionBudgetEvent<'static> {
        PermissionBudgetEvent {
            reason,
            token_bytes: 9001,
            permission_count: 412,
            audience: Some("https://api.example.com/orders"),
            organization_id: "org_budget",
            permission_status: Some(PermissionStatus::PdpRequired),
        }
    }

    /// THE COVENANT, mechanically: `record_permission_budget_event` writes a row at EVERY
    /// verbosity setting, `off` included.
    ///
    /// A test that only exercised the default verbosity would prove nothing about this,
    /// because the default is `standard` and every OTHER recorder in the module writes at
    /// `standard` too. The setting that matters is `off`, and it is in the list.
    ///
    /// Each setting gets its OWN scope, so "a row exists" cannot be satisfied by a row an
    /// earlier iteration wrote.
    #[tokio::test]
    async fn no_configuration_silences_the_permission_budget_event() {
        let db = TestDatabase::start().await;
        let env = Env::system();

        for verbosity in EVERY_VERBOSITY {
            // Exhaustive on purpose: a new variant fails to compile here rather than
            // silently escaping the cross product this test claims to cover.
            let label = match verbosity {
                DiagnosticVerbosity::Off => "off",
                DiagnosticVerbosity::Standard => "standard",
                DiagnosticVerbosity::Verbose => "verbose",
            };
            let (state, scope) = state_at(&db, &env, *verbosity).await;

            record_permission_budget_event(
                &state,
                scope,
                "cli_budget",
                sample_event(TokenSizeReason::BudgetOverflowBytes),
            )
            .await;

            let events = events_in(&state, scope).await;
            assert_eq!(
                events.len(),
                1,
                "diagnostics.verbosity = {label} must NOT be able to silence a permission \
                 budget event: issue #98's covenant is that no configuration produces a \
                 silent permission drop"
            );
            assert_eq!(
                events[0].token_type, "access_token",
                "a budget event is recorded against the ACCESS token at {label}"
            );
            assert_eq!(
                events[0].reason.as_deref(),
                Some("budget_overflow_bytes"),
                "the reason round-trips at {label}"
            );
        }
    }

    /// The CONTRAST that gives the test above its meaning: the recorder beside it IS
    /// verbosity gated, and at `off` it writes nothing.
    ///
    /// Same sink, same state, same scope shape, one differing setting. Without this half,
    /// "a row exists at off" could be explained by a build in which the gate never worked
    /// at all rather than by a deliberate exemption.
    #[tokio::test]
    async fn the_token_size_recorder_stays_verbosity_gated_at_off() {
        let db = TestDatabase::start().await;
        let env = Env::system();
        // Comfortably past ID_TOKEN_BLOAT_THRESHOLD_BYTES, so the threshold return is not
        // what suppresses the write. Not a real JWS: the recorder measures the length and
        // reads the claim count best effort, so an undecodable body records no count.
        let oversized = "x".repeat(4096);

        let (off_state, off_scope) = state_at(&db, &env, DiagnosticVerbosity::Off).await;
        record_token_size_event(&off_state, off_scope, "cli_bloat", &oversized).await;
        assert!(
            events_in(&off_state, off_scope).await.is_empty(),
            "record_token_size_event is verbosity gated: at off it must write nothing"
        );

        // Positive control: the SAME oversized token at standard DOES write, so the empty
        // read above is the gate and not a broken call.
        let (on_state, on_scope) = state_at(&db, &env, DiagnosticVerbosity::Standard).await;
        record_token_size_event(&on_state, on_scope, "cli_bloat", &oversized).await;
        let events = events_in(&on_state, on_scope).await;
        assert_eq!(
            events.len(),
            1,
            "the same oversized token at standard verbosity IS recorded"
        );
        assert_eq!(events[0].token_type, "id_token");
        assert_eq!(
            events[0].reason, None,
            "a bloat event carries no budget reason, which is what separates the two kinds"
        );
        assert_eq!(
            events[0].claim_count, None,
            "the comment above is measured, not asserted: this body is not a JWS, so the best \
             effort claim count decodes to nothing and an undecodable body records NO count"
        );
    }

    /// The pairing NEITHER the type nor the schema enforces, pinned on both recorders
    /// (issue #98): a row is `id_token` WITHOUT a reason, or `access_token` WITH one.
    ///
    /// It matters because the M9 warnings read discriminates on two different columns: the
    /// bloat half reads `token_type = 'id_token'` and the budget half reads
    /// `token_type = 'access_token'` and then a parseable `reason`. An `access_token` row
    /// carrying no reason would therefore be invisible to BOTH halves. `NewTokenSizeEvent`
    /// permits that combination, so the guarantee that no such row exists is caller
    /// discipline over exactly two callers, and this is what holds those two callers to it.
    #[tokio::test]
    async fn neither_recorder_can_write_a_row_invisible_to_both_warning_halves() {
        let db = TestDatabase::start().await;
        let env = Env::system();
        let (state, scope) = state_at(&db, &env, DiagnosticVerbosity::Standard).await;

        record_token_size_event(&state, scope, "cli_bloat", &"x".repeat(4096)).await;
        record_permission_budget_event(
            &state,
            scope,
            "cli_budget",
            sample_event(TokenSizeReason::BudgetOverflowBytes),
        )
        .await;

        let events = events_in(&state, scope).await;
        assert_eq!(events.len(), 2, "both recorders wrote");
        for event in &events {
            let reason_parses = event
                .reason
                .as_deref()
                .and_then(TokenSizeReason::from_wire)
                .is_some();
            let visible = if event.token_type == TokenSizeKind::IdToken.as_str() {
                event.reason.is_none()
            } else {
                event.token_type == TokenSizeKind::AccessToken.as_str() && reason_parses
            };
            assert!(
                visible,
                "every row a recorder writes must be visible to one of the two warning \
                 halves, and this one is visible to neither: {event:?}"
            );
        }
    }

    /// The recorder's OWN retention threading, measured (issue #98).
    ///
    /// The store-side retention test passes a literal window straight to the repository, so
    /// it says nothing about whether THIS function hands the configured value through. This
    /// one drives a real [`DiagnosticsConfig`] and a manual clock, which is what makes the
    /// threading the thing under test.
    ///
    /// Three observations, each of which kills a different way of getting it wrong: the
    /// first row is readable at all (the write landed), the second survives a write made
    /// INSIDE the window (a recorder that passed 0 would have pruned the first already),
    /// and both are gone after the window closes (a recorder that passed a huge window
    /// would have kept them).
    ///
    /// `retention_secs = 0` deserves its own sentence rather than only a mutant, because
    /// config admits it as a valid, safe posture: at 0 every row expires the instant it is
    /// written, so each insert prunes its predecessor and this sink holds AT MOST ONE
    /// budget row per scope. The covenant survives that (the token carries
    /// `permissions_status`); the convenience view does not.
    #[tokio::test]
    async fn the_recorder_threads_the_configured_retention() {
        let db = TestDatabase::start().await;
        let (env, clock) = Env::deterministic(UNIX_EPOCH, 0x98);
        let (state, scope) = state_configured(
            &db,
            &env,
            &DiagnosticsConfig {
                verbosity: DiagnosticVerbosity::Standard,
                retention_secs: 1,
            },
        )
        .await;

        let event = |permission_count: usize| PermissionBudgetEvent {
            permission_count,
            ..sample_event(TokenSizeReason::BudgetOverflowBytes)
        };

        record_permission_budget_event(&state, scope, "cli_budget", event(1)).await;
        assert_eq!(
            events_in(&state, scope).await.len(),
            1,
            "the first budget row is readable"
        );

        // A second write INSIDE the one second window. Both rows must stand: this is the
        // observation a recorder that threaded 0 (or any window shorter than the elapsed
        // time, which is none here) would fail.
        record_permission_budget_event(&state, scope, "cli_budget", event(2)).await;
        assert_eq!(
            events_in(&state, scope).await.len(),
            2,
            "a write inside the configured retention window must not prune its predecessor: \
             at retention_secs = 0 the sink would hold at most one row"
        );

        // Cross the window and write again. The prune runs on insert, so the write path is
        // what reclaims both expired rows; nothing waits on a background job.
        clock.advance(Duration::from_secs(2));
        record_permission_budget_event(&state, scope, "cli_budget", event(3)).await;
        let events = events_in(&state, scope).await;
        assert_eq!(
            events.len(),
            1,
            "both rows past the CONFIGURED window are pruned, so the recorder threaded \
             diagnostics.retention_secs rather than a store default"
        );
        assert_eq!(
            events[0].permission_count,
            Some(3),
            "the survivor is the newest row, so the prune removed the EXPIRED rows"
        );
    }

    /// Each of the five migration 0095 columns is WRITTEN and READ BACK, and none of them
    /// is a default that happens to look right.
    ///
    /// The values are chosen so a column that silently defaulted or that got crossed with
    /// its neighbour would fail: the two strings are not substrings of each other, the
    /// count is not the byte size, and the reason is not the first enum variant.
    #[tokio::test]
    async fn every_budget_column_round_trips_rather_than_defaulting() {
        let db = TestDatabase::start().await;
        let env = Env::system();
        let (state, scope) = state_at(&db, &env, DiagnosticVerbosity::Standard).await;

        record_permission_budget_event(
            &state,
            scope,
            "cli_budget",
            sample_event(TokenSizeReason::RolesOnlyStillOversize),
        )
        .await;

        let events = events_in(&state, scope).await;
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(
            event.reason.as_deref(),
            Some("roles_only_still_oversize"),
            "reason round-trips as the stable wire string, not as the default variant"
        );
        assert_eq!(
            TokenSizeReason::from_wire(event.reason.as_deref().expect("a reason")),
            Some(TokenSizeReason::RolesOnlyStillOversize),
            "and it parses back to the SAME variant the recorder was handed"
        );
        assert_eq!(
            event.audience.as_deref(),
            Some("https://api.example.com/orders"),
            "audience round-trips"
        );
        assert_eq!(
            event.organization_id.as_deref(),
            Some("org_budget"),
            "organization_id round-trips and is not crossed with the audience"
        );
        assert_eq!(
            event.permission_count,
            Some(412),
            "permission_count round-trips and is not the byte size"
        );
        assert_eq!(
            event.permission_status.as_deref(),
            Some("pdp_required"),
            "the status the TOKEN put on the wire round-trips, and is the variant the \
             recorder was handed rather than the first one"
        );
        assert_eq!(
            event.byte_size, 9001,
            "the byte size is the token size, distinct from the permission count"
        );
        assert_eq!(
            event.claim_count, None,
            "a budget event records no claim count, deliberately"
        );
    }

    /// A verdict that WITHHELD nothing carries no wire status (issue #98).
    ///
    /// `budget_approaching` means the claim was emitted, so no `permissions_status` went on
    /// the wire and there is nothing to record. A recorder that stamped a status onto an
    /// approach would be telling an operator a resource server was told to fall back when
    /// it was not.
    #[tokio::test]
    async fn an_approaching_verdict_records_no_wire_status() {
        let db = TestDatabase::start().await;
        let env = Env::system();
        let (state, scope) = state_at(&db, &env, DiagnosticVerbosity::Standard).await;

        record_permission_budget_event(
            &state,
            scope,
            "cli_budget",
            PermissionBudgetEvent {
                permission_status: None,
                ..sample_event(TokenSizeReason::BudgetApproaching)
            },
        )
        .await;

        let events = events_in(&state, scope).await;
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].reason.as_deref(),
            Some("budget_approaching"),
            "the verdict is the approach"
        );
        assert_eq!(
            events[0].permission_status, None,
            "nothing was withheld, so the token carried no permissions_status to record"
        );
    }

    /// A MULTI-AUDIENCE token records NO audience (issue #98).
    ///
    /// The budget produces one verdict for the whole token, and `AccessTokenTarget`
    /// permits several audiences, so a verdict is attributable to one resource server only
    /// when the token targets exactly one. Recording a NULL rather than picking the first
    /// is the difference between saying nothing and saying something false; the warnings
    /// read then renders the organization alone.
    #[tokio::test]
    async fn a_multi_audience_verdict_records_no_single_audience() {
        let db = TestDatabase::start().await;
        let env = Env::system();
        let (state, scope) = state_at(&db, &env, DiagnosticVerbosity::Standard).await;

        record_permission_budget_event(
            &state,
            scope,
            "cli_budget",
            PermissionBudgetEvent {
                audience: None,
                ..sample_event(TokenSizeReason::BudgetOverflowCount)
            },
        )
        .await;

        let events = events_in(&state, scope).await;
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].audience, None,
            "a verdict spanning several audiences names none of them"
        );
        assert_eq!(
            events[0].organization_id.as_deref(),
            Some("org_budget"),
            "the organization half of the address is still recorded"
        );
    }
}
