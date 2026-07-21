// SPDX-License-Identifier: MIT OR Apache-2.0

//! The read only flow inspector (issue #91, M9 admin diagnostics): a projection over the
//! flow state machine that NEVER mutates it.
//!
//! The inspector has TWO modes, and NEITHER calls the mutating engine ([`super::drive`],
//! which rotates the submit token, persists the next state, mints sessions, and records
//! jti/risk rows). Both are pure projections over data the caller already holds:
//!
//! - OBSERVE ([`observe`]): render an existing flow row's CURRENT position, the journey
//!   PLAN it sits within, a REDACTED projection of its persisted context, and the current
//!   node render, from a loaded [`FlowRecord`]. It reads nothing and writes nothing; the
//!   caller (the admin endpoint) does the ONE scoped, RLS forced row read.
//! - DRY REPLAY ([`dry_run`]): given a SUPPLIED context (the request body), walk the
//!   journey plan and evaluate the REAL policy evaluators, the step up requirement
//!   evaluation ([`crate::step_up::evaluate`], already pure) and the risk decision COMPUTE
//!   core ([`crate::risk::decide_from_signals`], the compute separated from its persist),
//!   with EVERY write disabled. It returns the SAME [`Satisfaction`] and [`RiskDecision`]
//!   the live path would for the same inputs (the fidelity guarantee), and it writes NO
//!   row anywhere: this module holds no store handle at all, so a dry run is structurally
//!   incapable of a side effect.
//!
//! The PLAN is the ordered [`FlowStateTag`] sequence per [`Journey`], sourced from
//! [`Journey::plan`], the ONE transition table the live engine also seeds its start state
//! from (see `start_state` in [`super`]), so the inspector can never drift from the states
//! the engine drives.
//!
//! REDACTION is structural: [`FlowContextView`] carries ONLY safe fields (the step, the
//! proven method tokens, the blind `usr_` subject handle, the connector slug, and two
//! booleans). It NEVER carries the flow's `submit_token` (that rides the [`FlowRecord`] but
//! has no field on any view here), and it NEVER carries the recovery `identifier` (a PII
//! contact), only a `has_identifier` boolean. A secret is unrepresentable, not scrubbed.

use serde::Serialize;

use ironauth_store::{FlowRecord, Scope};

use super::model::{Flow, FlowStateTag, Journey, Node, Transport};
use super::{PersistedState, build_flow, federation, login, mfa, recovery, registration};
use crate::risk::{RiskAction, RiskDecision, RiskLevel, SignalOutcome, decide_from_signals};
use crate::step_up::{self, AuthnRequirement, Satisfaction};

/// The primary factor method token a login flow proves first (the honest amr source, issue
/// #84): a plain password login proves `pwd`.
const PRIMARY_METHOD: &str = "pwd";

/// The second factor method token an in flow step up proves (issue #84): the combined amr
/// gains `mfa` once a genuine second factor completes.
const SECOND_FACTOR_METHOD: &str = "mfa";

/// A read only, structurally redacted projection of a flow's persisted context (issue #91).
///
/// Every field is a safe, non secret datum. There is deliberately NO field for the flow's
/// `submit_token` (the API CSRF handle, which lives on the [`FlowRecord`] but is never
/// projected) and NO field for the recovery `identifier` (a PII contact): the identifier is
/// reduced to the [`has_identifier`](FlowContextView::has_identifier) boolean, so a contact
/// value has NOWHERE to appear. A secret is unrepresentable here, not scrubbed after the
/// fact.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FlowContextView {
    /// The current state machine step.
    pub step: FlowStateTag,
    /// The primary auth method tokens proven so far (for example `["pwd"]`), the honest amr
    /// source. Bounded, non secret tokens.
    pub methods: Vec<String>,
    /// The subject the primary factor authenticated, a blind internal `usr_` handle (never
    /// raw PII), or [`None`] before a primary factor.
    pub subject: Option<String>,
    /// Whether a recovery identifier is held server side. The identifier VALUE (a PII
    /// contact) is NEVER projected; only its presence is, so the anti enumeration posture
    /// and the redaction line both hold.
    pub has_identifier: bool,
    /// Whether a second factor enrollment is pending (a bounded boolean; the enrollment
    /// credential id and its secret are never projected).
    pub enrolling: bool,
    /// The federation connector slug the launcher would redirect to (a non secret slug), or
    /// [`None`].
    pub connector: Option<String>,
}

impl FlowContextView {
    /// Project a persisted state into the redacted view, DROPPING the recovery identifier
    /// (kept as a boolean) and never touching a submit token (which is not on the state).
    fn from_state(state: &PersistedState) -> Self {
        Self {
            step: state.step,
            methods: state.methods.clone(),
            subject: state.subject.clone(),
            has_identifier: state.identifier.is_some(),
            enrolling: state.enroll_credential.is_some(),
            connector: state.connector.clone(),
        }
    }

    /// A synthetic context for a dry replay step, from the supplied subject and the tokens
    /// proven up to this point (no store row involved).
    fn synthetic(step: FlowStateTag, methods: Vec<String>, subject: Option<String>) -> Self {
        Self {
            step,
            methods,
            subject,
            has_identifier: false,
            enrolling: false,
            connector: None,
        }
    }
}

/// The ordered flow PLAN projection (issue #91): the journey and its ordered
/// [`FlowStateTag`] sequence, from [`Journey::plan`] (the ONE transition table the engine
/// shares).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FlowPlanView {
    /// The journey the plan is for.
    pub journey: Journey,
    /// The ordered state sequence the journey can occupy.
    pub steps: Vec<FlowStateTag>,
}

impl FlowPlanView {
    /// The plan for a journey, from the shared transition table.
    #[must_use]
    pub fn of(journey: Journey) -> Self {
        Self {
            journey,
            steps: journey.plan().to_vec(),
        }
    }
}

/// The OBSERVE projection of an existing flow (issue #91): its current position, the plan
/// it sits within, the redacted context, and the current node render, all read only.
#[derive(Debug, Clone, Serialize)]
pub struct ObserveProjection {
    /// The flow id (a scope embedded `flw_` id, non secret).
    pub flow_id: String,
    /// The journey this flow drives.
    pub journey: Journey,
    /// The transport it was created on.
    pub transport: Transport,
    /// The journey plan (the ordered state sequence).
    pub plan: FlowPlanView,
    /// The current state machine position.
    pub current: FlowStateTag,
    /// Whether the single use completion latch has tripped.
    pub completed: bool,
    /// Whether the flow has expired at the observation instant.
    pub expired: bool,
    /// The redacted flow context.
    pub context: FlowContextView,
    /// The current node render (the SAME [`Flow`] object model the engine renders), rebuilt
    /// read only from the row's current state. The `submit_token` is NOT part of this model
    /// (it rides the API envelope only), so the render carries no secret.
    pub node_render: Flow,
}

/// Why a flow could not be projected (issue #91): the stored row is malformed. The caller
/// maps this to a UNIFORM not found, so a corrupt row is never an oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectError {
    /// The row's journey, transport, or serialized state could not be parsed.
    Malformed,
}

/// Parse the stored transport string, or [`None`] for an unknown value.
fn parse_transport(raw: &str) -> Option<Transport> {
    match raw {
        "browser" => Some(Transport::Browser),
        "api" => Some(Transport::Api),
        _ => None,
    }
}

/// OBSERVE an existing flow row (issue #91): project its current position, plan, redacted
/// context, and current node render, WITHOUT any write and without calling the engine. The
/// caller has already done the ONE scoped, RLS forced read that produced `record`.
///
/// # Errors
///
/// [`InspectError::Malformed`] when the row's journey, transport, or serialized state is not
/// parseable (the caller answers a uniform not found).
pub fn observe(
    record: &FlowRecord,
    scope: Scope,
    now_micros: i64,
) -> Result<ObserveProjection, InspectError> {
    let journey = Journey::parse(&record.journey).ok_or(InspectError::Malformed)?;
    let transport = parse_transport(&record.transport).ok_or(InspectError::Malformed)?;
    let persisted: PersistedState =
        serde_json::from_str(&record.state).map_err(|_| InspectError::Malformed)?;
    let current = persisted.step;
    let context = FlowContextView::from_state(&persisted);

    // The current node render, reusing the ENGINE'S own node builders and the same
    // deterministic `build_flow` assembly (no side effects). For a state whose live form
    // needs ceremony material not held on the row (the MFA enrollment secret), the code
    // entry form shape is rendered instead of synthesizing a secret: the inspector never
    // reconstructs an enrollment secret (it is not on the row and must not be invented).
    let nodes = canonical_nodes(
        current,
        transport,
        &record.id,
        persisted.connector.as_deref(),
    );
    let node_render = build_flow(
        scope,
        record,
        transport,
        journey,
        current,
        nodes,
        Vec::new(),
    );

    Ok(ObserveProjection {
        flow_id: record.id.clone(),
        journey,
        transport,
        plan: FlowPlanView::of(journey),
        current,
        completed: record.is_completed(),
        expired: record.is_expired(now_micros),
        context,
        node_render,
    })
}

/// The canonical nodes for a state (issue #91), reusing the SAME pure node builders the
/// live engine and the golden corpus call, so the inspector render matches the engine's.
/// The MFA enrollment state renders the code entry form shape (never the enrollment secret,
/// which is not held on the row).
fn canonical_nodes(
    state: FlowStateTag,
    transport: Transport,
    flow_id: &str,
    connector: Option<&str>,
) -> Vec<Node> {
    match state {
        FlowStateTag::IdentifierPassword => login::start_nodes(transport, flow_id),
        FlowStateTag::RegistrationDetails => registration::start_nodes(transport, flow_id),
        FlowStateTag::RegistrationAck => registration::ack_nodes(),
        // The enroll state renders the code entry form shape (the same second factor code
        // input the challenge state uses), NEVER the enrollment secret: the secret is not on
        // the row and the inspector must not synthesize one.
        FlowStateTag::MfaChallenge | FlowStateTag::MfaEnroll => {
            mfa::challenge_start_nodes(transport, flow_id)
        }
        FlowStateTag::RecoveryStart => recovery::start_nodes(transport, flow_id),
        FlowStateTag::RecoveryAck => recovery::ack_nodes(transport, flow_id, false),
        FlowStateTag::FederationStart => connector
            .map(|slug| federation::start_nodes(transport, flow_id, slug))
            .unwrap_or_default(),
        FlowStateTag::Completed => Vec::new(),
    }
}

// ===========================================================================
// The DRY REPLAY: the supplied context walk over the REAL evaluators, no writes.
// ===========================================================================

/// A supplied risk signal for a dry replay (issue #91): the operator's what if scenario, a
/// bounded name, a level, and whether it is a hard deny. NOT read from any store; the dry
/// run evaluates exactly the scenario supplied.
#[derive(Debug, Clone)]
pub struct RiskSignalInput {
    /// The signal name (mapped to the engine's bounded vocabulary; an unknown name folds to
    /// `external_signal`).
    pub name: String,
    /// This signal's contribution level.
    pub level: RiskLevel,
    /// Whether this signal alone justifies a block (a hard deny).
    pub hard_deny: bool,
}

/// The risk scenario a dry replay evaluates (issue #91): the supplied signals plus the
/// deployment posture switches the real dispatch reads. Defaults mirror
/// [`ironauth_config::RiskConfig`].
#[derive(Debug, Clone)]
pub struct RiskInput {
    /// The supplied signals (the what if scenario).
    pub signals: Vec<RiskSignalInput>,
    /// Whether a new device fired (drives the notify rung).
    pub new_device_fired: bool,
    /// The step up threshold the score is compared against, or [`None`] for "never force".
    pub threshold: Option<RiskLevel>,
    /// Whether a hard deny blocks (the `block_on_high` posture).
    pub block_on_high: bool,
    /// Whether a new device notifies (the `notify_on_new_device` posture).
    pub notify_on_new_device: bool,
}

/// The dry replay input (issue #91): the supplied what if context the caller (the admin
/// endpoint) parsed from the request body. The pure walk holds NO store handle, so it cannot
/// read or write anything. The acr floor and the achieved acr are canonicalized and the acr
/// order defaulted INSIDE [`dry_run`], so the caller passes only strings and never needs the
/// step up internals.
#[derive(Debug, Clone)]
pub struct DryRunInput {
    /// The journey whose plan to walk.
    pub journey: Journey,
    /// The subject the context carries (a blind `usr_` handle), or [`None`].
    pub subject: Option<String>,
    /// The required acr floor (an alias like `mfa` or a full canonical acr), or [`None`].
    pub required_acr: Option<String>,
    /// The achieved acr the supplied authentication reached (canonicalized on evaluation).
    pub achieved_acr: String,
    /// The maximum authentication age in seconds the requirement imposes, or [`None`].
    pub max_auth_age_secs: Option<u64>,
    /// The recorded authentication instant, or [`None`] (which fails an age bound closed).
    pub auth_time_micros: Option<i64>,
    /// The clock instant to evaluate against.
    pub now_micros: i64,
    /// The acr order to compare under, or [`None`] for the canonical deployment ladder.
    pub order: Option<Vec<String>>,
    /// The risk scenario, or [`None`] to skip the risk evaluator.
    pub risk: Option<RiskInput>,
}

/// One evaluated step of a dry replay (issue #91): the plan state, whether the supplied
/// scenario reaches it, which policy (if any) governs it, the real evaluators' decisions,
/// and the redacted context at this step.
#[derive(Debug, Clone, Serialize)]
pub struct DryRunStep {
    /// The plan state this step is.
    pub step: FlowStateTag,
    /// Whether the supplied scenario reaches this state.
    pub reached: bool,
    /// The policy that governs the transition out of this step, or [`None`].
    pub policy: Option<String>,
    /// The step up requirement evaluation at this step, when it governs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step_up: Option<StepUpDecisionView>,
    /// The risk decision at this step, when it governs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk: Option<RiskDecisionView>,
    /// The redacted context at this step.
    pub context: FlowContextView,
}

/// The step up requirement evaluation projection (issue #91), from the REAL
/// [`crate::step_up::evaluate`].
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StepUpDecisionView {
    /// The bounded outcome (`satisfied` or `step_up_required`).
    pub outcome: String,
    /// Whether the achieved acr did not satisfy the floor.
    pub acr_unmet: bool,
    /// Whether the authentication age window lapsed.
    pub age_lapsed: bool,
    /// The required acr floor, or [`None`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_acr: Option<String>,
    /// The achieved acr the evaluation compared.
    pub achieved_acr: String,
}

impl StepUpDecisionView {
    /// Project a [`Satisfaction`] into the view.
    fn from_satisfaction(
        satisfaction: Satisfaction,
        requirement: &AuthnRequirement,
        achieved_acr: &str,
    ) -> Self {
        let (outcome, acr_unmet, age_lapsed) = match satisfaction {
            Satisfaction::Satisfied => ("satisfied", false, false),
            Satisfaction::NeedsStepUp {
                acr_unmet,
                age_lapsed,
            } => ("step_up_required", acr_unmet, age_lapsed),
        };
        Self {
            outcome: outcome.to_owned(),
            acr_unmet,
            age_lapsed,
            required_acr: requirement.min_acr.clone(),
            achieved_acr: achieved_acr.to_owned(),
        }
    }
}

/// The risk decision projection (issue #91), from the REAL
/// [`crate::risk::decide_from_signals`]. Carries the SAME safe field projection PR3 records
/// (the signal NAMES and levels), never a raw IP or count.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RiskDecisionView {
    /// The combined level (`low` / `med` / `high`).
    pub level: String,
    /// The dispatched action (`allow` / `block` / `challenge` / `notify`).
    pub action: String,
    /// Whether the new device signal fired.
    pub new_device_fired: bool,
    /// The contributing signals, projected to name and level only.
    pub signals: Vec<RiskSignalView>,
}

/// A contributing risk signal projection (issue #91): the NAME and level only, mirroring
/// PR3's [`ironauth_store::PolicyTraceSignal`] redaction.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RiskSignalView {
    /// The signal name.
    pub name: String,
    /// The signal's contribution level.
    pub level: String,
}

impl RiskDecisionView {
    /// Project a [`RiskDecision`] into the safe view.
    fn from_decision(decision: &RiskDecision) -> Self {
        Self {
            level: decision.level.as_str().to_owned(),
            action: decision.action.as_str().to_owned(),
            new_device_fired: decision.new_device_fired,
            signals: decision
                .outcomes
                .iter()
                .map(|outcome| RiskSignalView {
                    name: outcome.name.to_owned(),
                    level: outcome.level.as_str().to_owned(),
                })
                .collect(),
        }
    }
}

/// The full DRY REPLAY projection (issue #91): the plan, the per step decisions, and the
/// terminal state the supplied scenario reaches. ZERO rows are written to produce it.
#[derive(Debug, Clone, Serialize)]
pub struct DryRunProjection {
    /// The journey walked.
    pub journey: Journey,
    /// The journey plan.
    pub plan: FlowPlanView,
    /// The per step evaluations.
    pub steps: Vec<DryRunStep>,
    /// The terminal state the supplied scenario reaches.
    pub terminal: FlowStateTag,
}

/// Map a supplied signal name to the engine's bounded, static signal vocabulary (issue
/// #91). A known internal signal keeps its name; anything else folds to `external_signal`,
/// so a hostile name has a bounded, inert projection.
fn signal_name(raw: &str) -> &'static str {
    match raw {
        "new_device" => "new_device",
        "impossible_travel" => "impossible_travel",
        "ip_reputation" => "ip_reputation",
        "velocity" => "velocity",
        _ => "external_signal",
    }
}

/// Evaluate the supplied risk scenario through the REAL compute core (issue #91):
/// [`crate::risk::decide_from_signals`], the SAME function the live [`crate::risk::evaluate`]
/// path dispatches through, so the decision is byte identical to the live path for the same
/// signals. NO store read, NO write.
fn evaluate_risk(input: &RiskInput) -> RiskDecision {
    let outcomes: Vec<SignalOutcome> = input
        .signals
        .iter()
        .map(|signal| SignalOutcome {
            name: signal_name(&signal.name),
            level: signal.level,
            hard_deny: signal.hard_deny,
            // A fixed, non secret marker: the dry run supplies the level and name, never a
            // live measured value.
            value: "dry-run".to_owned(),
        })
        .collect();
    decide_from_signals(
        outcomes,
        input.new_device_fired,
        input.threshold,
        input.block_on_high,
        input.notify_on_new_device,
    )
}

/// DRY REPLAY a supplied context over the journey plan (issue #91): evaluate the REAL step
/// up and risk evaluators with EVERY write disabled, and project which plan states the
/// scenario reaches. This function holds NO store handle, so it is structurally incapable of
/// a side effect: it reads only its argument and returns a projection.
///
/// The step up requirement evaluation and the risk decision are attached to the plan's FIRST
/// step (the primary factor, where the live login engine consults them). When either forces
/// a step up (the requirement is unmet, or risk challenges), the reachable path threads the
/// login MFA challenge state before completing; otherwise it completes straight from the
/// primary step. For a non login journey the evaluators still report their verdict on the
/// supplied context, and the reachable path is the journey's own plan.
#[must_use]
pub fn dry_run(input: &DryRunInput) -> DryRunProjection {
    let journey = input.journey;
    let plan = journey.plan();

    // Resolve the acr order (the deployment ladder by default) and canonicalize the supplied
    // acr floor and achieved acr, so an operator supplied alias like `mfa` gates against the
    // SAME canonical value the live path compares.
    let order = input
        .order
        .clone()
        .unwrap_or_else(step_up::default_acr_order);
    let requirement = AuthnRequirement {
        min_acr: input
            .required_acr
            .as_deref()
            .map(step_up::canonical_step_up_acr),
        max_auth_age_secs: input.max_auth_age_secs,
    };
    let achieved_acr = step_up::canonical_step_up_acr(&input.achieved_acr);

    // The REAL step up evaluator (already pure), verbatim.
    let satisfaction = step_up::evaluate(
        &requirement,
        &achieved_acr,
        input.auth_time_micros,
        input.now_micros,
        &order,
    );
    let step_up_view =
        StepUpDecisionView::from_satisfaction(satisfaction, &requirement, &achieved_acr);

    // The REAL risk compute core (compute separated from persist), over the supplied
    // scenario, when one is supplied.
    let risk_decision = input.risk.as_ref().map(evaluate_risk);
    let risk_view = risk_decision.as_ref().map(RiskDecisionView::from_decision);

    // Whether the supplied context forces a step up: the requirement is unmet OR risk
    // challenges. This is the SAME composition the live login engine makes (the step up gate
    // raises its requirement on a risk challenge).
    let step_up_needed = matches!(satisfaction, Satisfaction::NeedsStepUp { .. })
        || risk_decision
            .as_ref()
            .is_some_and(|decision| decision.action == RiskAction::Challenge);
    let blocked = risk_decision
        .as_ref()
        .is_some_and(|decision| decision.action == RiskAction::Block);

    let outcome = ScenarioOutcome {
        step_up_needed,
        blocked,
    };
    let mut steps = Vec::with_capacity(plan.len());
    for (index, &state) in plan.iter().enumerate() {
        let projected = step_projection(
            state,
            index == 0,
            outcome,
            &step_up_view,
            risk_view.as_ref(),
        );
        steps.push(DryRunStep {
            step: state,
            reached: projected.reached,
            policy: projected.policy,
            step_up: projected.step_up,
            risk: projected.risk,
            context: FlowContextView::synthetic(state, projected.methods, input.subject.clone()),
        });
    }

    let terminal = terminal_state(plan, outcome);
    DryRunProjection {
        journey,
        plan: FlowPlanView::of(journey),
        steps,
        terminal,
    }
}

/// The resolved outcome of the supplied scenario (issue #91): whether it forces a step up
/// and whether it is blocked. Drives which plan states the walk marks reached.
#[derive(Debug, Clone, Copy)]
struct ScenarioOutcome {
    /// The requirement is unmet or risk challenges: the login threads the MFA challenge.
    step_up_needed: bool,
    /// A hard deny blocks: the login never completes (the uniform failure).
    blocked: bool,
}

/// The projection of one plan state for the dry replay walk (issue #91).
struct StepProjection {
    /// The policy governing the transition out of this step, or [`None`].
    policy: Option<String>,
    /// The step up requirement evaluation attached to this step, when it governs.
    step_up: Option<StepUpDecisionView>,
    /// The risk decision attached to this step, when it governs.
    risk: Option<RiskDecisionView>,
    /// Whether the supplied scenario reaches this state.
    reached: bool,
    /// The proven method tokens at this step.
    methods: Vec<String>,
}

/// The per step projection for the dry replay walk (issue #91): which policy governs the
/// step, the decisions attached to it, whether it is reached, and the proven method tokens
/// at it.
fn step_projection(
    state: FlowStateTag,
    is_first: bool,
    outcome: ScenarioOutcome,
    step_up_view: &StepUpDecisionView,
    risk_view: Option<&RiskDecisionView>,
) -> StepProjection {
    if is_first {
        // The primary factor step: the real evaluators are consulted here.
        return StepProjection {
            policy: Some("step_up,risk".to_owned()),
            step_up: Some(step_up_view.clone()),
            risk: risk_view.cloned(),
            reached: true,
            methods: vec![PRIMARY_METHOD.to_owned()],
        };
    }
    match state {
        // The login step up states are reached only when the scenario forces a step up (and
        // is not blocked). The challenge state is the modeled remediation; the enroll state
        // depends on the subject's enrolled factors, which a pure dry run does not read, so
        // it is projected as not reached.
        FlowStateTag::MfaChallenge => StepProjection {
            policy: None,
            step_up: None,
            risk: None,
            reached: outcome.step_up_needed && !outcome.blocked,
            methods: vec![PRIMARY_METHOD.to_owned()],
        },
        FlowStateTag::MfaEnroll => StepProjection {
            policy: None,
            step_up: None,
            risk: None,
            reached: false,
            methods: vec![PRIMARY_METHOD.to_owned()],
        },
        FlowStateTag::Completed => {
            // The completion is reached unless the scenario blocks. The proven methods gain
            // the second factor token when a step up was threaded.
            let mut methods = vec![PRIMARY_METHOD.to_owned()];
            if outcome.step_up_needed {
                methods.push(SECOND_FACTOR_METHOD.to_owned());
            }
            StepProjection {
                policy: None,
                step_up: None,
                risk: None,
                reached: !outcome.blocked,
                methods,
            }
        }
        // Every other plan state (the non login journeys' render/ack/launcher states) is on
        // the scenario's path.
        _ => StepProjection {
            policy: None,
            step_up: None,
            risk: None,
            reached: !outcome.blocked,
            methods: Vec::new(),
        },
    }
}

/// The terminal state the supplied scenario reaches (issue #91): a blocked login never
/// completes (it stays on the primary step, the uniform failure), a step up threads the MFA
/// challenge to completion, and otherwise the plan's last state is the terminal.
fn terminal_state(plan: &[FlowStateTag], outcome: ScenarioOutcome) -> FlowStateTag {
    let start = plan
        .first()
        .copied()
        .unwrap_or(FlowStateTag::IdentifierPassword);
    if outcome.blocked {
        return start;
    }
    if outcome.step_up_needed && plan.contains(&FlowStateTag::MfaChallenge) {
        // A login step up threads the challenge, then completes.
        return FlowStateTag::Completed;
    }
    plan.last().copied().unwrap_or(start)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::golden::golden_flows;

    fn order() -> Vec<String> {
        step_up::default_acr_order()
    }

    const PWD: &str = "urn:ironauth:acr:pwd";
    const MFA: &str = "urn:ironauth:acr:mfa";

    #[test]
    fn plan_matches_engine_start_and_covers_every_golden_state() {
        // The anti drift gate (issue #91): the inspector's plan is the SAME transition table
        // the engine seeds its start state from, so it can never drift from the states the
        // engine drives.
        //
        // 1. Every creatable journey's engine start state equals its plan's first state:
        //    `start_state` (the engine's entry) sources the start tag from `plan()[0]`.
        for journey in [
            Journey::Login,
            Journey::Registration,
            Journey::Recovery,
            Journey::Federation,
        ] {
            let connector = (journey == Journey::Federation).then_some("acme-oidc");
            let (persisted, _nodes) = super::super::start_state(
                journey,
                Transport::Browser,
                "flw_test0000000000000000000000",
                connector,
            )
            .expect("a creatable journey has a start state");
            assert_eq!(
                persisted.step,
                journey.plan()[0],
                "{journey:?} start state must equal plan[0]"
            );
        }

        // 2. The MFA pseudo journey is not a creation entry: its plan is empty and
        //    `start_state` refuses it.
        assert!(Journey::Mfa.plan().is_empty(), "the MFA plan is empty");
        assert!(
            super::super::start_state(
                Journey::Mfa,
                Transport::Browser,
                "flw_test0000000000000000000000",
                None
            )
            .is_none(),
            "the MFA journey is not a creation entry"
        );

        // 3. Every state the engine actually renders (the golden corpus, itself CI gated
        //    against the engine's node builders) is a member of its journey's plan, so a new
        //    engine state cannot be added without appearing in the plan.
        for golden in golden_flows() {
            let plan = golden.flow.journey.plan();
            assert!(
                plan.contains(&golden.flow.state),
                "golden {} has state {:?} outside the {:?} plan {:?}",
                golden.name,
                golden.flow.state,
                golden.flow.journey,
                plan
            );
        }
    }

    #[test]
    fn dry_run_step_up_is_faithful_to_the_real_evaluator() {
        // The fidelity guarantee (issue #91): the dry run's step up outcome equals a DIRECT
        // call to the real `step_up::evaluate` for the same inputs (it is literally the same
        // function).
        let order = order();
        let now = 2_000_000_000_000_000_i64;
        let requirement = AuthnRequirement {
            min_acr: Some(MFA.to_owned()),
            max_auth_age_secs: None,
        };
        let input = DryRunInput {
            journey: Journey::Login,
            subject: Some("usr_dryrun".to_owned()),
            required_acr: Some(MFA.to_owned()),
            achieved_acr: PWD.to_owned(),
            max_auth_age_secs: None,
            auth_time_micros: Some(now),
            now_micros: now,
            order: Some(order.clone()),
            risk: None,
        };
        let projection = dry_run(&input);

        // The direct evaluator verdict.
        let direct = step_up::evaluate(&requirement, PWD, Some(now), now, &order);
        assert_eq!(
            direct,
            Satisfaction::NeedsStepUp {
                acr_unmet: true,
                age_lapsed: false
            }
        );

        // The dry run attaches it to the first (primary) step, and it agrees.
        let first = &projection.steps[0];
        let step_up = first.step_up.as_ref().expect("step up on the primary step");
        assert_eq!(step_up.outcome, "step_up_required");
        assert!(step_up.acr_unmet && !step_up.age_lapsed);
        // A pwd achieved acr against an mfa floor forces the MFA challenge, then completes.
        assert!(
            projection
                .steps
                .iter()
                .any(|s| s.step == FlowStateTag::MfaChallenge && s.reached),
            "the challenge is reached"
        );
        assert_eq!(projection.terminal, FlowStateTag::Completed);
    }

    #[test]
    fn dry_run_risk_is_faithful_to_the_real_compute_core() {
        // The fidelity guarantee for risk (issue #91): the dry run's risk decision equals a
        // DIRECT call to `risk::decide_from_signals` for the same signals.
        let order = order();
        let now = 2_000_000_000_000_000_i64;
        let signals = vec![
            RiskSignalInput {
                name: "velocity".to_owned(),
                level: RiskLevel::Med,
                hard_deny: false,
            },
            RiskSignalInput {
                name: "impossible_travel".to_owned(),
                level: RiskLevel::Med,
                hard_deny: false,
            },
        ];
        let input = DryRunInput {
            journey: Journey::Login,
            subject: None,
            required_acr: None,
            achieved_acr: PWD.to_owned(),
            max_auth_age_secs: None,
            auth_time_micros: Some(now),
            now_micros: now,
            order: Some(order),
            risk: Some(RiskInput {
                signals: signals.clone(),
                new_device_fired: false,
                threshold: Some(RiskLevel::Med),
                block_on_high: true,
                notify_on_new_device: true,
            }),
        };
        let projection = dry_run(&input);

        // The direct compute core over the SAME signals (two MED signals combine to HIGH).
        let outcomes: Vec<SignalOutcome> = signals
            .iter()
            .map(|s| SignalOutcome {
                name: signal_name(&s.name),
                level: s.level,
                hard_deny: s.hard_deny,
                value: "dry-run".to_owned(),
            })
            .collect();
        let direct = decide_from_signals(outcomes, false, Some(RiskLevel::Med), true, true);
        assert_eq!(
            direct.level,
            RiskLevel::High,
            "two MED signals corroborate to HIGH"
        );
        assert_eq!(direct.action, RiskAction::Challenge);

        let first = &projection.steps[0];
        let risk = first.risk.as_ref().expect("risk on the primary step");
        assert_eq!(risk.level, direct.level.as_str());
        assert_eq!(risk.action, direct.action.as_str());
        assert_eq!(risk.signals.len(), 2);
        // A risk challenge threads the MFA challenge to completion.
        assert_eq!(projection.terminal, FlowStateTag::Completed);
    }

    #[test]
    fn dry_run_block_stays_on_the_primary_step() {
        // A hard deny signal blocks: the login never completes (the uniform failure), so the
        // terminal is the primary step and the completion is not reached.
        let now = 2_000_000_000_000_000_i64;
        let input = DryRunInput {
            journey: Journey::Login,
            subject: None,
            required_acr: None,
            achieved_acr: PWD.to_owned(),
            max_auth_age_secs: None,
            auth_time_micros: Some(now),
            now_micros: now,
            order: Some(order()),
            risk: Some(RiskInput {
                signals: vec![RiskSignalInput {
                    name: "ip_reputation".to_owned(),
                    level: RiskLevel::High,
                    hard_deny: true,
                }],
                new_device_fired: false,
                threshold: None,
                block_on_high: true,
                notify_on_new_device: true,
            }),
        };
        let projection = dry_run(&input);
        assert_eq!(projection.terminal, FlowStateTag::IdentifierPassword);
        assert!(
            projection
                .steps
                .iter()
                .any(|s| s.step == FlowStateTag::Completed && !s.reached),
            "completion is not reached when blocked"
        );
    }

    #[test]
    fn redaction_corpus_leaks_no_secret_sentinel() {
        // The structural redaction corpus for the inspector projections (issue #91), the
        // sibling of the client auth and policy trace corpora. It stuffs known secret / token
        // / PII sentinels into every secret bearing position of a persisted flow state, builds
        // the redacted context view AND the dry run projection, serializes them, and asserts
        // NO sentinel appears. The guarantee is structural: the context view has no field for
        // the submit token (it is not even on the persisted state) and no field for the
        // recovery identifier (a PII contact), which is reduced to a boolean, so a secret has
        // NOWHERE to go.
        use std::fmt::Write as _;

        const SENTINELS: &[&str] = &[
            "SUPERSECRETSUBMITTOKENSENTINEL",
            "RECOVERYIDENTIFIERPIISENTINEL",
            "ENROLLMENTSECRETSENTINEL",
        ];

        let mut serialized = String::new();

        // A persisted state with sentinels stuffed into every text position: the recovery
        // identifier (PII), the enrollment credential id, and (as a control) the subject and
        // connector. The submit token is NOT on the persisted state at all (it rides the
        // FlowRecord), so it is structurally absent here.
        let persisted = PersistedState {
            step: FlowStateTag::RecoveryAck,
            subject: Some("usr_safehandle".to_owned()),
            methods: vec!["pwd".to_owned()],
            enroll_credential: Some("ENROLLMENTSECRETSENTINEL".to_owned()),
            identifier: Some("RECOVERYIDENTIFIERPIISENTINEL".to_owned()),
            connector: Some("acme-oidc".to_owned()),
        };
        let context = FlowContextView::from_state(&persisted);
        write!(
            serialized,
            "{context:?}{}",
            serde_json::to_string(&context).expect("serialize context")
        )
        .expect("write");

        // A dry run projection built from a context carrying a sentinel subject (a blind
        // handle, never a claim value) and a submit token sentinel that has no field to land
        // in.
        let projection = dry_run(&DryRunInput {
            journey: Journey::Login,
            subject: Some("usr_safehandle".to_owned()),
            required_acr: Some(MFA.to_owned()),
            achieved_acr: PWD.to_owned(),
            max_auth_age_secs: Some(300),
            auth_time_micros: None,
            now_micros: 2_000_000_000_000_000_i64,
            order: Some(order()),
            risk: Some(RiskInput {
                signals: vec![RiskSignalInput {
                    name: "SUPERSECRETSUBMITTOKENSENTINEL".to_owned(),
                    level: RiskLevel::Med,
                    hard_deny: false,
                }],
                new_device_fired: true,
                threshold: Some(RiskLevel::Med),
                block_on_high: true,
                notify_on_new_device: true,
            }),
        });
        write!(
            serialized,
            "{projection:?}{}",
            serde_json::to_string(&projection).expect("serialize projection")
        )
        .expect("write");

        // Positive control: a SAFE field DID make it through (the projection is real).
        assert!(
            serialized.contains("usr_safehandle") && serialized.contains("recovery_ack"),
            "the safe fields must be recorded (the projection is real)"
        );
        // The recovery identifier is reduced to a boolean; the enrollment credential is
        // reduced to a boolean; the hostile signal name is folded to the bounded vocabulary.
        assert!(
            serialized.contains("has_identifier") && serialized.contains("external_signal"),
            "the identifier is a boolean and a hostile signal name folds to the vocabulary"
        );

        for sentinel in SENTINELS {
            assert!(
                !serialized.contains(sentinel),
                "a secret sentinel leaked into an inspector projection: {sentinel}"
            );
        }
    }
}
