// SPDX-License-Identifier: MIT OR Apache-2.0

//! Golden-path replay (issue #92, PR 7): a recorded journey TRANSCRIPT re-executed against a
//! compiled journey's ROUTING, so behavioral drift between flow versions fails a CI gate.
//!
//! ## What a replay checks, and what it does not
//!
//! A journey artifact owns TOPOLOGY and ROUTING (the steps, the transitions, the decision
//! guards). The step EXECUTORS (verify a password, run a second factor) are shared, fixed Rust
//! that every journey version calls the same way, so they are NOT what drifts between versions.
//! A golden-path replay therefore re-executes only the ROUTING: given a recorded SCENARIO (a
//! sequence of per-step outcome [`crate::SignalSet`]s plus the subject context the guards read),
//! it walks the [`CompiledJourney`]'s guarded transitions and asserts the resulting step SEQUENCE
//! (and its terminal) matches the recorded golden. A version whose routing changed (a guard
//! edited, a transition added or reordered) makes the recorded transcript diverge, and the gate
//! fails, forcing the author to record the new behavior deliberately.
//!
//! ## The routing rule is the engine's
//!
//! [`run`] walks a step's guarded edges in DOCUMENT ORDER and takes the first whose guard is
//! absent or evaluates true, threading a [`StepKind::Decision`] step in-call (a decision renders
//! nothing and routes onward under the same signals), exactly as the OIDC crate's `drive_custom`
//! routes a live custom flow. So a replay observes precisely the routing a real flow would, with
//! no clock, no entropy, and no database: the evaluation context is pinned by the transcript, and
//! the evaluator ([`evaluate`]) is pure.
//!
//! ## The engine-faithful context set
//!
//! A replay is only trustworthy if the context it assembles matches what the LIVE engine
//! assembles, so a passing replay can never mask a routing the engine would take differently. The
//! engine's `assemble_eval_context` populates the ENGINE-LIVE inputs: the step outcome `signals`,
//! the proven `method_tokens`, the blind `subject_handle`, the sealed `subject_traits` document,
//! and (as of issue #355) the `risk` decision on the post-login hop. It HARDCODES the two remaining
//! not-live sources empty: `subject_groups` and `subject_scopes`. `crate::eval::source_is_engine_live`
//! is the shared LIVE / NOT-LIVE truth the engine and the load-time validator agree on. This module
//! assembles the context the SAME way ([`base_context`]): it honors a transcript's signals, method
//! tokens, subject handle, traits, and risk (all engine-faithful), and it assembles empty groups and
//! scopes regardless of the transcript, exactly as the engine does. To keep a golden corpus from
//! ever RELYING on an unpopulated field (which would read faithfully today yet route differently if
//! the engine wired it), [`JourneyTranscript::check_engine_faithful`] REJECTS a transcript step that
//! sets `groups` or `scopes`; the CI harness enforces it, so an unfaithful transcript can never
//! land. Those two transcript fields are RESERVED for when the engine populates them.
//!
//! ## Purity discipline
//!
//! This module is a PURE value function, like the rest of the crate: no clock, no entropy, no
//! I/O. The transcript and the compiled journey are values; a replay reads them and returns a
//! [`ReplayReport`]. The CI script does the file I/O (reading the corpus, writing a regenerated
//! transcript); the library never touches the filesystem.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::artifact::{StepId, StepKind};
use crate::compile::CompiledJourney;
use crate::eval::{
    EvalContext, FlowContext, OutcomeSignal, RiskLevel, RiskView, SignalSet, evaluate,
};

/// A recorded journey transcript (issue #92, PR 7): a whole golden-path run captured as the
/// scenario that drives it, replayed against a compiled journey to catch routing drift.
///
/// The `journey_id` and `engine_version` identify the journey artifact this transcript replays
/// against; the CI harness pairs a transcript with its artifact and refuses a mismatch before
/// compiling. `steps` is the ordered sequence of routing hops the run takes, one per rendering
/// step (the entry first), each recording the signals and subject context that drive the hop and
/// the outcome the routing is expected to produce. Comments are FIRST-CLASS data, preserved
/// through a serde round-trip. An unknown property is a hard parse error (`deny_unknown_fields`),
/// so a typo cannot silently drop a field and weaken the golden.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JourneyTranscript {
    /// The document-local id of the journey artifact this transcript replays against.
    pub journey_id: String,
    /// The orchestration ABI version the journey artifact was authored for. The harness refuses a
    /// transcript whose declared engine version disagrees with the artifact's.
    pub engine_version: u32,
    /// An optional human-readable description of the scenario (data, round-trip-safe).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub description: Option<String>,
    /// The ordered routing hops of the run, one per rendering step (the entry first). The last hop
    /// reaches a terminal step, so a well-formed golden path is a COMPLETE run.
    pub steps: Vec<TranscriptStep>,
}

/// One recorded routing hop (issue #92, PR 7): the inputs that drive the routing at the current
/// rendering step, and the outcome the routing is expected to produce.
///
/// The `signals` are the step's emitted outcome signals (the routing inputs a guard reads under
/// the `signals` source); `subject` carries any subject context a guard reads (traits, groups,
/// scopes, risk, proven method tokens), omitted when the hop's guards read only signals. `expect`
/// is the outcome: the next rendering step, or the terminal step that completes the run. An
/// unknown property is a hard parse error (`deny_unknown_fields`).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TranscriptStep {
    /// An optional human-readable comment about the hop (data, round-trip-safe).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub comment: Option<String>,
    /// The outcome signals asserted at this hop (the routing inputs). A signal not listed reads as
    /// `false`, so an empty set means every signal is `false`.
    #[serde(skip_serializing_if = "TranscriptSignals::is_empty", default)]
    pub signals: TranscriptSignals,
    /// The subject context a guard reads at this hop, or [`None`] when the guards read only
    /// signals.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub subject: Option<TranscriptSubject>,
    /// The routing outcome this hop is expected to produce.
    pub expect: ExpectedHop,
}

/// The set of outcome signals asserted at a hop (issue #92, PR 7): the transcript's serde form of
/// a [`SignalSet`]. It serializes as a sorted array of the `snake_case` signal names that hold, so
/// the recorded form is minimal and a regenerated transcript is byte-stable. A name absent from
/// the array reads as `false`.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(transparent)]
pub struct TranscriptSignals(BTreeSet<SignalName>);

impl TranscriptSignals {
    /// A transcript signal set holding exactly the given signals.
    #[must_use]
    pub fn of(signals: impl IntoIterator<Item = SignalName>) -> Self {
        Self(signals.into_iter().collect())
    }

    /// Whether no signal is asserted (every signal reads as `false`).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The engine [`SignalSet`] this transcript form denotes.
    #[must_use]
    pub fn to_signal_set(&self) -> SignalSet {
        let mut set = SignalSet::new();
        for name in &self.0 {
            set = set.with(name.to_outcome(), true);
        }
        set
    }
}

/// A serializable outcome-signal name (issue #92, PR 7): the transcript's closed enum mirror of
/// [`OutcomeSignal`], so a transcript names a signal by its `snake_case` wire form and an unknown
/// name is a hard parse error.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SignalName {
    /// The first factor was proven ([`OutcomeSignal::PrimaryVerified`]).
    PrimaryVerified,
    /// A second factor is required before completion ([`OutcomeSignal::MfaRequired`]).
    MfaRequired,
    /// A second factor must be enrolled before completion ([`OutcomeSignal::EnrollRequired`]).
    EnrollRequired,
    /// Progressive profiling is pending before completion ([`OutcomeSignal::ProfilingPending`]).
    ProfilingPending,
}

impl SignalName {
    /// The engine [`OutcomeSignal`] this name denotes.
    #[must_use]
    pub fn to_outcome(self) -> OutcomeSignal {
        match self {
            SignalName::PrimaryVerified => OutcomeSignal::PrimaryVerified,
            SignalName::MfaRequired => OutcomeSignal::MfaRequired,
            SignalName::EnrollRequired => OutcomeSignal::EnrollRequired,
            SignalName::ProfilingPending => OutcomeSignal::ProfilingPending,
        }
    }
}

/// The subject context a guard reads at a hop (issue #92, PR 7): the parts of the evaluation
/// context that come from the subject rather than the step's signals. Every field is optional and
/// defaults empty, so a transcript records only the context its journey's guards actually read. An
/// unknown property is a hard parse error (`deny_unknown_fields`).
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TranscriptSubject {
    /// The subject's sealed identity trait document (addressed by an RFC 6901 pointer under the
    /// `subject_traits` source), or JSON null when the guards read no trait.
    #[serde(skip_serializing_if = "Value::is_null", default)]
    pub traits: Value,
    /// The subject's group memberships (tested by a group membership predicate).
    #[serde(skip_serializing_if = "BTreeSet::is_empty", default)]
    pub groups: BTreeSet<String>,
    /// The subject's granted scopes (tested by a scope membership predicate).
    #[serde(skip_serializing_if = "BTreeSet::is_empty", default)]
    pub scopes: BTreeSet<String>,
    /// The method tokens proven so far in the run (read as the `flow` source `/method_tokens`
    /// set).
    #[serde(skip_serializing_if = "BTreeSet::is_empty", default)]
    pub method_tokens: BTreeSet<String>,
    /// The blind `usr_` subject handle (read as the `flow` source `/subject`), never end-user
    /// data.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub subject_handle: String,
    /// The risk decision the guards read, or [`None`] when no guard reads risk.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub risk: Option<TranscriptRisk>,
}

/// The risk decision a guard reads at a hop (issue #92, PR 7): the transcript's serde form of a
/// [`RiskView`]. An unknown property is a hard parse error (`deny_unknown_fields`).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TranscriptRisk {
    /// The categorical risk level (read as the `risk` source `/level`).
    pub level: TranscriptRiskLevel,
    /// The numeric risk score (read as the `risk` source `/score`).
    pub score: u32,
}

impl TranscriptRisk {
    /// The engine [`RiskView`] this transcript form denotes.
    ///
    /// A transcript may carry a nonzero `score`, but the engine always emits `score: 0` (the risk
    /// verdict exposes a level, not a numeric score). This is faithful by vacuity: the risk `/score`
    /// source is validator-rejected (issue #355), so no compiled guard can ever route on the score,
    /// and the difference is unreachable at replay time.
    #[must_use]
    pub fn to_view(self) -> RiskView {
        RiskView {
            level: self.level.to_level(),
            score: self.score,
        }
    }
}

/// A serializable risk level (issue #92, PR 7): the transcript's closed enum mirror of
/// [`RiskLevel`], named by its `snake_case` wire form.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptRiskLevel {
    /// Low risk ([`RiskLevel::Low`]).
    Low,
    /// Medium risk ([`RiskLevel::Medium`]).
    Medium,
    /// High risk ([`RiskLevel::High`]).
    High,
}

impl TranscriptRiskLevel {
    /// The engine [`RiskLevel`] this name denotes.
    #[must_use]
    pub fn to_level(self) -> RiskLevel {
        match self {
            TranscriptRiskLevel::Low => RiskLevel::Low,
            TranscriptRiskLevel::Medium => RiskLevel::Medium,
            TranscriptRiskLevel::High => RiskLevel::High,
        }
    }
}

/// The routing outcome a transcript hop expects (issue #92, PR 7): either the run ADVANCES to the
/// named next rendering step, or it reaches the named TERMINAL step and completes. It serializes
/// as a single-key object, `{"step": "<id>"}` or `{"terminal": "<id>"}`, so the recorded
/// expectation names both the step and whether it ends the run, and a version that turns a step
/// terminal (or the reverse) is a divergence.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedHop {
    /// Routing advances to this next rendering step; the run continues.
    Step(StepId),
    /// Routing reaches this terminal step; the run completes.
    Terminal(StepId),
}

impl ExpectedHop {
    /// The expected step id and whether it is a terminal (a completion).
    #[must_use]
    fn parts(&self) -> (&str, bool) {
        match self {
            ExpectedHop::Step(id) => (id.as_str(), false),
            ExpectedHop::Terminal(id) => (id.as_str(), true),
        }
    }
}

impl fmt::Display for ExpectedHop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExpectedHop::Step(id) => write!(f, "step {id}"),
            ExpectedHop::Terminal(id) => write!(f, "terminal {id}"),
        }
    }
}

/// The result of replaying a transcript against a compiled journey (issue #92, PR 7): a MATCH when
/// every hop routed exactly as recorded and the run reached its terminal, or a precise DIVERGENCE
/// otherwise. The replay is TOTAL: a malformed or drifted transcript (an unexpected next step, a
/// dead end where a hop was expected, a hop past the terminal, a run that never completes) is a
/// divergence with a precise location, never a panic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayReport {
    /// Every recorded hop routed as expected and the run reached its terminal.
    Match,
    /// The routing diverged from the transcript.
    Divergence(Divergence),
}

impl ReplayReport {
    /// Whether the replay matched the transcript (no divergence).
    #[must_use]
    pub fn is_match(&self) -> bool {
        matches!(self, ReplayReport::Match)
    }
}

/// A precise routing divergence (issue #92, PR 7): the hop index that diverged, the step the hop
/// routed from, the outcome the transcript expected (when the divergence is at a recorded hop),
/// and the outcome the routing actually produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Divergence {
    /// The zero-based index of the diverging hop within the transcript's `steps` (or the length of
    /// `steps` for a run that ended without completing).
    pub step_index: usize,
    /// The step id the diverging hop routed from.
    pub from: StepId,
    /// The outcome the transcript expected at this hop, or [`None`] for the tail case where the
    /// transcript ended but the run never reached a terminal.
    pub expected: Option<ExpectedHop>,
    /// The outcome the compiled routing actually produced.
    pub observed: ObservedHop,
}

impl fmt::Display for Divergence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.expected {
            Some(expected) => write!(
                f,
                "hop {} from {}: expected {}, but routing {}",
                self.step_index, self.from, expected, self.observed
            ),
            None => write!(
                f,
                "hop {} from {}: routing {}",
                self.step_index, self.from, self.observed
            ),
        }
    }
}

/// What the compiled routing produced at a diverging hop (issue #92, PR 7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObservedHop {
    /// Routing advanced to `to`; `terminal` is whether that step ends the run.
    Advanced {
        /// The step id routing advanced to.
        to: StepId,
        /// Whether `to` is a terminal step (a completion).
        terminal: bool,
    },
    /// No transition guard matched from the current step: routing dead-ended.
    DeadEnded,
    /// A hop was recorded, but the run had already reached its terminal (the transcript continues
    /// past completion).
    PastTerminal,
    /// The transcript ended, but the run never reached a terminal step (an incomplete golden
    /// path).
    Incomplete,
    /// The in-call routing did not settle on a rendering or terminal step within the step bound (a
    /// mis-compiled table; [`crate::compile`] rejects one, so a well-formed corpus never hits
    /// this).
    Unsettled,
}

impl fmt::Display for ObservedHop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ObservedHop::Advanced { to, terminal: true } => write!(f, "reached terminal {to}"),
            ObservedHop::Advanced {
                to,
                terminal: false,
            } => write!(f, "advanced to step {to}"),
            ObservedHop::DeadEnded => write!(f, "dead-ended (no guard matched)"),
            ObservedHop::PastTerminal => write!(f, "had already completed"),
            ObservedHop::Incomplete => write!(f, "never reached a terminal"),
            ObservedHop::Unsettled => write!(f, "did not settle on a step"),
        }
    }
}

/// The settled outcome of routing one hop from a rendering step, threading decision steps in-call.
enum HopOutcome {
    /// Routing settled on a rendering or terminal step.
    Landed {
        /// The step routing settled on.
        to: StepId,
        /// Whether that step is a terminal (a completion).
        terminal: bool,
    },
    /// No transition guard matched from `at`: routing dead-ended.
    DeadEnd {
        /// The step routing dead-ended at.
        at: StepId,
    },
    /// Routing did not settle within the step bound (a mis-compiled table).
    Unsettled,
}

/// Replay a transcript against a compiled journey (issue #92, PR 7): a PURE, DETERMINISTIC, TOTAL
/// walk. Starting at the compiled entry, each transcript hop assembles the evaluation context from
/// the hop's recorded signals and subject context, walks the current step's guarded transitions in
/// DOCUMENT ORDER taking the first absent-or-true guard (threading a decision step in-call, exactly
/// as the engine's `drive_custom` routes a live flow), and asserts the settled step matches the
/// hop's expectation. A terminal hop completes the run.
///
/// The context is pinned by the transcript (no clock, no entropy), and the evaluator is pure, so a
/// replay observes precisely the routing a live flow would, with no database. The report is a
/// [`ReplayReport::Match`] when every hop routed as recorded and the run completed, or a precise
/// [`Divergence`] otherwise (an unexpected next step, a dead end, a hop past the terminal, or a
/// run that never completes).
#[must_use]
pub fn run(compiled: &CompiledJourney, transcript: &JourneyTranscript) -> ReplayReport {
    let mut cursor = compiled.entry.clone();
    let mut completed = false;
    for (index, step) in transcript.steps.iter().enumerate() {
        if completed {
            // The run reached its terminal on an earlier hop, yet the transcript records more: the
            // golden path is longer than the routing allows.
            return ReplayReport::Divergence(Divergence {
                step_index: index,
                from: cursor,
                expected: Some(step.expect.clone()),
                observed: ObservedHop::PastTerminal,
            });
        }
        let base = base_context(step);
        match route_hop(compiled, &cursor, &base) {
            HopOutcome::Landed { to, terminal } => {
                let (expected_id, expected_terminal) = step.expect.parts();
                if to != expected_id || terminal != expected_terminal {
                    return ReplayReport::Divergence(Divergence {
                        step_index: index,
                        from: cursor,
                        expected: Some(step.expect.clone()),
                        observed: ObservedHop::Advanced { to, terminal },
                    });
                }
                if terminal {
                    completed = true;
                } else {
                    cursor = to;
                }
            }
            HopOutcome::DeadEnd { at } => {
                return ReplayReport::Divergence(Divergence {
                    step_index: index,
                    from: at,
                    expected: Some(step.expect.clone()),
                    observed: ObservedHop::DeadEnded,
                });
            }
            HopOutcome::Unsettled => {
                return ReplayReport::Divergence(Divergence {
                    step_index: index,
                    from: cursor,
                    expected: Some(step.expect.clone()),
                    observed: ObservedHop::Unsettled,
                });
            }
        }
    }
    if completed {
        ReplayReport::Match
    } else {
        // Every recorded hop matched, but the run never routed into a terminal: an incomplete
        // golden path (or an empty transcript).
        ReplayReport::Divergence(Divergence {
            step_index: transcript.steps.len(),
            from: cursor,
            expected: None,
            observed: ObservedHop::Incomplete,
        })
    }
}

/// Why a transcript could not be regenerated (issue #92, PR 7): the compiled routing does not
/// produce a clean, complete sequence for the recorded signals, so its expectations cannot be
/// derived. Carries the hop index and the reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegenerateError {
    /// The zero-based index of the hop whose outcome could not be derived.
    pub step_index: usize,
    /// Why the outcome could not be derived.
    pub reason: RegenerateReason,
}

/// Why a hop's expected outcome could not be derived during regeneration (issue #92, PR 7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegenerateReason {
    /// Routing dead-ended at the hop (no guard matched), so there is no next step to record.
    DeadEnded {
        /// The step routing dead-ended at.
        at: StepId,
    },
    /// The routing had already reached a terminal, so a further recorded hop cannot be derived.
    PastTerminal,
    /// Routing did not settle on a step within the step bound (a mis-compiled table).
    Unsettled,
}

impl fmt::Display for RegenerateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.reason {
            RegenerateReason::DeadEnded { at } => write!(
                f,
                "hop {}: routing dead-ended at {at} (no guard matched)",
                self.step_index
            ),
            RegenerateReason::PastTerminal => write!(
                f,
                "hop {}: routing had already completed, so the hop cannot be recorded",
                self.step_index
            ),
            RegenerateReason::Unsettled => write!(
                f,
                "hop {}: routing did not settle on a step",
                self.step_index
            ),
        }
    }
}

impl std::error::Error for RegenerateError {}

/// A subject-context field the transcript set that the engine does not yet populate (issue #92,
/// PR 7): the reason [`JourneyTranscript::check_engine_faithful`] rejects a transcript. Naming the
/// field keeps the error precise and operator-safe (it names a context field, never a value).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnfaithfulField {
    /// The subject's group memberships (the engine assembles these empty; `source_is_engine_live`
    /// keeps the subject-groups source not-live pending a membership model, issue #355).
    Groups,
    /// The subject's granted scopes (the engine assembles these empty; `source_is_engine_live`
    /// keeps the subject-scopes source not-live pending a membership model, issue #355).
    Scopes,
}

impl UnfaithfulField {
    /// The transcript field name this reason names.
    #[must_use]
    fn as_str(self) -> &'static str {
        match self {
            UnfaithfulField::Groups => "groups",
            UnfaithfulField::Scopes => "scopes",
        }
    }
}

/// Why a transcript is not faithful to the current engine (issue #92, PR 7): a hop's subject
/// context sets a field ([`UnfaithfulField`]) the engine's `assemble_eval_context` does not populate
/// (empty groups and scopes; `source_is_engine_live` in `crate::eval` is the shared truth for which
/// sources are live, issue #355). Replaying such a transcript would read faithfully TODAY (the
/// replay ignores the field, exactly as the engine does), yet the recorded expectation would
/// silently stop reflecting real behavior if the engine wired the field, so the harness refuses it
/// up front. Carries the hop index and the offending field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnfaithfulTranscript {
    /// The zero-based index of the hop whose subject context set an unpopulated field.
    pub step_index: usize,
    /// The unpopulated field the hop set.
    pub field: UnfaithfulField,
}

impl fmt::Display for UnfaithfulTranscript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "hop {}: subject {} is not yet populated by the engine (see issue #355); a transcript \
             routing on it would not reflect real behavior",
            self.step_index,
            self.field.as_str()
        )
    }
}

impl std::error::Error for UnfaithfulTranscript {}

impl JourneyTranscript {
    /// Refuse a transcript that routes on a subject-context field the engine does not populate
    /// (issue #92, PR 7): a load-time fidelity lint. The engine's `assemble_eval_context` hardcodes
    /// empty `subject_groups` and `subject_scopes` (the sources `source_is_engine_live` keeps
    /// not-live, issue #355), so a transcript that sets either would replay against those ignored
    /// values TODAY yet drift from real behavior if the engine wired them. The CI harness runs this
    /// before replaying, so a committed golden corpus can never carry an unfaithful transcript. The
    /// engine-faithful subject inputs (`method_tokens`, `subject_handle`, `traits`, and `risk`,
    /// which is engine-live as of #355) are always allowed.
    ///
    /// # Errors
    ///
    /// An [`UnfaithfulTranscript`] naming the first hop that sets `groups` or `scopes`.
    pub fn check_engine_faithful(&self) -> Result<(), UnfaithfulTranscript> {
        for (index, step) in self.steps.iter().enumerate() {
            if let Some(subject) = &step.subject {
                let unfaithful = if !subject.groups.is_empty() {
                    Some(UnfaithfulField::Groups)
                } else if !subject.scopes.is_empty() {
                    Some(UnfaithfulField::Scopes)
                } else {
                    // The risk is engine-live as of issue #355 (`source_is_engine_live`), so a
                    // transcript MAY set it; the replay honors it in `base_context`.
                    None
                };
                if let Some(field) = unfaithful {
                    return Err(UnfaithfulTranscript {
                        step_index: index,
                        field,
                    });
                }
            }
        }
        Ok(())
    }

    /// Return a copy of this transcript with each hop's `expect` replaced by the outcome the
    /// compiled routing actually produces for that hop's recorded signals and subject context
    /// (issue #92, PR 7): the REGENERATION the CI gate offers so an author who changes routing
    /// updates the goldens by a reviewable diff rather than by hand.
    ///
    /// The recorded signals, subject context, comments, and step count are preserved verbatim;
    /// only the derived `expect` fields change. Regeneration is IDEMPOTENT: regenerating a
    /// transcript that already matches the routing reproduces it exactly, so `run` on a
    /// regenerated transcript is always a [`ReplayReport::Match`].
    ///
    /// # Errors
    ///
    /// A [`RegenerateError`] when the routing cannot produce a clean sequence for the recorded
    /// signals: a hop that dead-ends, a hop past a terminal, or an unsettled table. A hand-authored
    /// golden path that reaches its terminal never triggers this.
    pub fn regenerated(
        &self,
        compiled: &CompiledJourney,
    ) -> Result<JourneyTranscript, RegenerateError> {
        let mut cursor = compiled.entry.clone();
        let mut completed = false;
        let mut steps = Vec::with_capacity(self.steps.len());
        for (index, step) in self.steps.iter().enumerate() {
            if completed {
                return Err(RegenerateError {
                    step_index: index,
                    reason: RegenerateReason::PastTerminal,
                });
            }
            let base = base_context(step);
            let expect = match route_hop(compiled, &cursor, &base) {
                HopOutcome::Landed { to, terminal } => {
                    if terminal {
                        completed = true;
                        ExpectedHop::Terminal(to)
                    } else {
                        cursor.clone_from(&to);
                        ExpectedHop::Step(to)
                    }
                }
                HopOutcome::DeadEnd { at } => {
                    return Err(RegenerateError {
                        step_index: index,
                        reason: RegenerateReason::DeadEnded { at },
                    });
                }
                HopOutcome::Unsettled => {
                    return Err(RegenerateError {
                        step_index: index,
                        reason: RegenerateReason::Unsettled,
                    });
                }
            };
            steps.push(TranscriptStep {
                comment: step.comment.clone(),
                signals: step.signals.clone(),
                subject: step.subject.clone(),
                expect,
            });
        }
        Ok(JourneyTranscript {
            journey_id: self.journey_id.clone(),
            engine_version: self.engine_version,
            description: self.description.clone(),
            steps,
        })
    }
}

/// Assemble the base evaluation context for a hop from its recorded signals and subject context
/// (issue #92, PR 7), the SAME way the engine's `assemble_eval_context` does. The engine-faithful
/// inputs are honored from the transcript: the `signals`, the `method_tokens`, the
/// `subject_handle`, the `subject_traits`, and (as of issue #355) the `risk`. The two the engine
/// still hardcodes are assembled the engine's way REGARDLESS of the transcript: empty
/// `subject_groups` and `subject_scopes`. [`JourneyTranscript::check_engine_faithful`] rejects a
/// transcript that sets those two, so a valid corpus never carries a value the engine would ignore.
/// The `step_id` is set per cursor by [`route_hop`], so it is left empty here.
fn base_context(step: &TranscriptStep) -> EvalContext {
    let signals = step.signals.to_signal_set();
    let subject = step.subject.clone().unwrap_or_default();
    // The risk is engine-live as of issue #355 (`source_is_engine_live`), so the replay honors the
    // transcript's risk (a `None` transcript risk is the engine's default Low, exactly as the
    // no-live-signal login hop assembles it).
    let risk = subject
        .risk
        .map_or_else(RiskView::default, TranscriptRisk::to_view);
    EvalContext {
        flow: FlowContext {
            step_id: String::new(),
            method_tokens: subject.method_tokens,
            subject_handle: subject.subject_handle,
            signals,
        },
        subject_traits: subject.traits,
        // The engine still hardcodes groups and scopes empty (`source_is_engine_live` keeps them
        // not-live), so the replay assembles them the same way to stay faithful; the load lint
        // guarantees the transcript never routed on them.
        subject_groups: BTreeSet::new(),
        subject_scopes: BTreeSet::new(),
        risk,
    }
}

/// Route one hop from a rendering step, threading decision steps in-call (issue #92, PR 7): the
/// SAME document-order-first-true-guard walk the engine's `drive_custom` runs. Each in-call hop
/// re-seats the context's `step_id` on the cursor (a decision guard may read `/step_id`) under the
/// hop's fixed signals and subject, and takes the first guarded edge that applies. A decision step
/// continues the walk; a rendering or terminal step settles it. The hop count is bounded by the
/// step count, so a mis-compiled cyclic table cannot loop forever.
fn route_hop(compiled: &CompiledJourney, start: &str, base: &EvalContext) -> HopOutcome {
    let mut cursor = start.to_owned();
    for _ in 0..=compiled.steps.len() {
        let mut ctx = base.clone();
        ctx.flow.step_id.clone_from(&cursor);
        let Some(next_id) = choose_edge(compiled, &cursor, &ctx) else {
            return HopOutcome::DeadEnd { at: cursor };
        };
        let Some(next) = compiled.step(&next_id) else {
            // A dangling target cannot survive compilation, so this only keeps the walk total.
            return HopOutcome::DeadEnd { at: cursor };
        };
        match &next.kind {
            StepKind::Terminal => {
                return HopOutcome::Landed {
                    to: next_id,
                    terminal: true,
                };
            }
            // A decision renders nothing and routes onward under the same signals: continue in-call.
            StepKind::Decision => {
                cursor = next_id;
            }
            // Every renderable executor kind (the login/MFA/profiling kinds and, from PR 8a, the
            // mint-family registration and recovery kinds) settles the walk: control lands there and
            // awaits the next submission. The mint itself happens on that step's own submission, not
            // on this routing hop, so a landed mint-family step is non-terminal here.
            StepKind::IdentifierPassword
            | StepKind::MfaChallenge
            | StepKind::MfaEnroll
            | StepKind::ProgressiveProfiling
            | StepKind::Registration
            | StepKind::RecoveryStart
            | StepKind::RecoveryVerify => {
                return HopOutcome::Landed {
                    to: next_id,
                    terminal: false,
                };
            }
            // A subflow_call is inlined away at compile time and an unknown kind never compiles, so
            // either on a compiled table is a corrupt table: treat it as a dead end, never a panic.
            StepKind::SubflowCall | StepKind::Unknown(_) => {
                return HopOutcome::DeadEnd { at: cursor };
            }
        }
    }
    HopOutcome::Unsettled
}

/// Choose the first guarded edge that applies from `from` (issue #92, PR 7): document order, first
/// whose guard is absent or evaluates true. This is byte-for-byte the engine `drive_custom`'s
/// `choose_edge` rule; an evaluation error (only the depth guard, which a type-checked predicate
/// never hits) is treated as a non-match, never fail-open.
fn choose_edge(compiled: &CompiledJourney, from: &str, ctx: &EvalContext) -> Option<StepId> {
    for edge in compiled.edges(from) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{
        CmpOp, FieldRef, FieldSource, JOURNEY_ENGINE_VERSION, JOURNEY_SCHEMA_VERSION, Journey,
        Literal, Predicate, Step, Transition,
    };
    use crate::compile::compile;

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

    /// The conditional-MFA fixture: primary routes to the MFA step when a second factor is
    /// required, otherwise straight to the terminal.
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

    fn hop(signals: &[SignalName], expect: ExpectedHop) -> TranscriptStep {
        TranscriptStep {
            comment: None,
            signals: TranscriptSignals::of(signals.iter().copied()),
            subject: None,
            expect,
        }
    }

    /// The stepped-up golden path: a second factor is required, so primary routes to the MFA step,
    /// then MFA completes to the terminal.
    fn stepped_up_transcript() -> JourneyTranscript {
        JourneyTranscript {
            journey_id: "login_conditional_mfa".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            description: Some("Stepped-up path.".to_owned()),
            steps: vec![
                hop(
                    &[SignalName::PrimaryVerified, SignalName::MfaRequired],
                    ExpectedHop::Step("mfa".to_owned()),
                ),
                hop(
                    &[SignalName::PrimaryVerified],
                    ExpectedHop::Terminal("done".to_owned()),
                ),
            ],
        }
    }

    /// The password-only golden path: no second factor is required, so primary routes straight to
    /// the terminal.
    fn password_only_transcript() -> JourneyTranscript {
        JourneyTranscript {
            journey_id: "login_conditional_mfa".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            description: Some("Password-only path.".to_owned()),
            steps: vec![hop(
                &[SignalName::PrimaryVerified],
                ExpectedHop::Terminal("done".to_owned()),
            )],
        }
    }

    #[test]
    fn both_conditional_mfa_golden_paths_replay_and_match() {
        let compiled = compile(&conditional_mfa_journey()).expect("compiles");
        assert_eq!(
            run(&compiled, &stepped_up_transcript()),
            ReplayReport::Match
        );
        assert_eq!(
            run(&compiled, &password_only_transcript()),
            ReplayReport::Match
        );
    }

    #[test]
    fn a_wrong_expected_next_step_is_a_precise_divergence() {
        let compiled = compile(&conditional_mfa_journey()).expect("compiles");
        // The stepped-up scenario routes primary -> mfa, but the transcript expects done.
        let transcript = JourneyTranscript {
            journey_id: "login_conditional_mfa".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            description: None,
            steps: vec![hop(
                &[SignalName::PrimaryVerified, SignalName::MfaRequired],
                ExpectedHop::Terminal("done".to_owned()),
            )],
        };
        let report = run(&compiled, &transcript);
        assert_eq!(
            report,
            ReplayReport::Divergence(Divergence {
                step_index: 0,
                from: "primary".to_owned(),
                expected: Some(ExpectedHop::Terminal("done".to_owned())),
                observed: ObservedHop::Advanced {
                    to: "mfa".to_owned(),
                    terminal: false,
                },
            })
        );
        assert!(!report.is_match());
    }

    #[test]
    fn a_routing_change_makes_the_recorded_transcript_diverge() {
        // A drifted journey version: the primary step's FIRST edge is now unguarded to mfa, so the
        // password-only scenario (mfa_required false) that used to route straight to done now
        // routes to mfa. The recorded password-only golden must catch the drift.
        let mut drifted = conditional_mfa_journey();
        drifted.transitions[0].guard = None;
        let compiled = compile(&drifted).expect("compiles");
        let report = run(&compiled, &password_only_transcript());
        assert_eq!(
            report,
            ReplayReport::Divergence(Divergence {
                step_index: 0,
                from: "primary".to_owned(),
                expected: Some(ExpectedHop::Terminal("done".to_owned())),
                observed: ObservedHop::Advanced {
                    to: "mfa".to_owned(),
                    terminal: false,
                },
            })
        );
    }

    #[test]
    fn an_expected_step_that_no_longer_exists_diverges_precisely() {
        // A transcript that expects a step id the routing never produces (a renamed or deleted
        // step) is a precise divergence: routing advanced to the real step, not the ghost.
        let compiled = compile(&conditional_mfa_journey()).expect("compiles");
        let transcript = JourneyTranscript {
            journey_id: "login_conditional_mfa".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            description: None,
            steps: vec![hop(
                &[SignalName::PrimaryVerified, SignalName::MfaRequired],
                ExpectedHop::Step("second_factor".to_owned()),
            )],
        };
        assert_eq!(
            run(&compiled, &transcript),
            ReplayReport::Divergence(Divergence {
                step_index: 0,
                from: "primary".to_owned(),
                expected: Some(ExpectedHop::Step("second_factor".to_owned())),
                observed: ObservedHop::Advanced {
                    to: "mfa".to_owned(),
                    terminal: false,
                },
            })
        );
    }

    #[test]
    fn a_scenario_that_dead_ends_is_a_precise_divergence_never_a_panic() {
        // A journey whose only edge out of primary is guarded on mfa_required == true, with no
        // fallback: a scenario with mfa_required false matches no guard and dead-ends.
        let journey = Journey {
            schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
            id: "guarded_only".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            entry: "primary".to_owned(),
            comment: None,
            steps: vec![
                step("primary", StepKind::IdentifierPassword, Some("password")),
                step("done", StepKind::Terminal, None),
            ],
            transitions: vec![Transition {
                from: "primary".to_owned(),
                to: "done".to_owned(),
                guard: Some(mfa_required_guard(true)),
                comment: None,
            }],
            subflows: None,
            subflow_definitions: None,
        };
        let compiled = compile(&journey).expect("compiles");
        let transcript = JourneyTranscript {
            journey_id: "guarded_only".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            description: None,
            // mfa_required is false (absent), so no guard matches.
            steps: vec![hop(
                &[SignalName::PrimaryVerified],
                ExpectedHop::Terminal("done".to_owned()),
            )],
        };
        assert_eq!(
            run(&compiled, &transcript),
            ReplayReport::Divergence(Divergence {
                step_index: 0,
                from: "primary".to_owned(),
                expected: Some(ExpectedHop::Terminal("done".to_owned())),
                observed: ObservedHop::DeadEnded,
            })
        );
    }

    #[test]
    fn a_hop_past_the_terminal_is_a_divergence() {
        let compiled = compile(&conditional_mfa_journey()).expect("compiles");
        // The password-only run completes on hop 0, so a second recorded hop is past the terminal.
        let transcript = JourneyTranscript {
            journey_id: "login_conditional_mfa".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            description: None,
            steps: vec![
                hop(
                    &[SignalName::PrimaryVerified],
                    ExpectedHop::Terminal("done".to_owned()),
                ),
                hop(
                    &[SignalName::PrimaryVerified],
                    ExpectedHop::Terminal("done".to_owned()),
                ),
            ],
        };
        assert_eq!(
            run(&compiled, &transcript),
            ReplayReport::Divergence(Divergence {
                step_index: 1,
                from: "primary".to_owned(),
                expected: Some(ExpectedHop::Terminal("done".to_owned())),
                observed: ObservedHop::PastTerminal,
            })
        );
    }

    #[test]
    fn a_transcript_that_never_completes_is_a_divergence() {
        let compiled = compile(&conditional_mfa_journey()).expect("compiles");
        // Only the first hop of the stepped-up path is recorded, so the run stops on mfa without
        // completing.
        let transcript = JourneyTranscript {
            journey_id: "login_conditional_mfa".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            description: None,
            steps: vec![hop(
                &[SignalName::PrimaryVerified, SignalName::MfaRequired],
                ExpectedHop::Step("mfa".to_owned()),
            )],
        };
        assert_eq!(
            run(&compiled, &transcript),
            ReplayReport::Divergence(Divergence {
                step_index: 1,
                from: "mfa".to_owned(),
                expected: None,
                observed: ObservedHop::Incomplete,
            })
        );
    }

    #[test]
    fn regeneration_is_idempotent_and_yields_a_matching_transcript() {
        let compiled = compile(&conditional_mfa_journey()).expect("compiles");
        for original in [stepped_up_transcript(), password_only_transcript()] {
            let regenerated = original.regenerated(&compiled).expect("regenerates");
            // The already-correct golden regenerates to itself, and running it matches.
            assert_eq!(regenerated, original);
            assert_eq!(run(&compiled, &regenerated), ReplayReport::Match);
            // Regeneration is idempotent: a second pass is a no-op.
            assert_eq!(
                regenerated.regenerated(&compiled).expect("again"),
                regenerated
            );
        }
    }

    #[test]
    fn regeneration_repairs_a_drifted_expected_step() {
        let compiled = compile(&conditional_mfa_journey()).expect("compiles");
        // A transcript whose expects are wrong regenerates to the correct routing outcome.
        let wrong = JourneyTranscript {
            journey_id: "login_conditional_mfa".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            description: None,
            steps: vec![hop(
                &[SignalName::PrimaryVerified, SignalName::MfaRequired],
                // Wrong: routing actually advances to mfa.
                ExpectedHop::Terminal("done".to_owned()),
            )],
        };
        // The wrong transcript diverges before regeneration.
        assert!(!run(&compiled, &wrong).is_match());
        let repaired = wrong.regenerated(&compiled).expect("regenerates");
        assert_eq!(
            repaired.steps[0].expect,
            ExpectedHop::Step("mfa".to_owned())
        );
    }

    #[test]
    fn regeneration_refuses_a_dead_ending_scenario() {
        let journey = Journey {
            schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
            id: "guarded_only".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            entry: "primary".to_owned(),
            comment: None,
            steps: vec![
                step("primary", StepKind::IdentifierPassword, Some("password")),
                step("done", StepKind::Terminal, None),
            ],
            transitions: vec![Transition {
                from: "primary".to_owned(),
                to: "done".to_owned(),
                guard: Some(mfa_required_guard(true)),
                comment: None,
            }],
            subflows: None,
            subflow_definitions: None,
        };
        let compiled = compile(&journey).expect("compiles");
        let transcript = JourneyTranscript {
            journey_id: "guarded_only".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            description: None,
            steps: vec![hop(
                &[SignalName::PrimaryVerified],
                ExpectedHop::Step("x".to_owned()),
            )],
        };
        let error = transcript.regenerated(&compiled).expect_err("dead-ends");
        assert_eq!(error.step_index, 0);
        assert!(matches!(error.reason, RegenerateReason::DeadEnded { .. }));
    }

    #[test]
    fn a_transcript_round_trips_through_json_with_its_comments() {
        let transcript = JourneyTranscript {
            journey_id: "login_conditional_mfa".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            description: Some("Stepped-up path.".to_owned()),
            steps: vec![TranscriptStep {
                comment: Some("Second factor required.".to_owned()),
                signals: TranscriptSignals::of([
                    SignalName::PrimaryVerified,
                    SignalName::MfaRequired,
                ]),
                subject: None,
                expect: ExpectedHop::Step("mfa".to_owned()),
            }],
        };
        let json = serde_json::to_string_pretty(&transcript).expect("serialize");
        let parsed: JourneyTranscript = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, transcript);
        // The expected hop serializes as a single-key object.
        assert!(json.contains("\"step\": \"mfa\""));
        // The signal set serializes as a sorted array of wire names.
        assert!(json.contains("\"primary_verified\""));
    }

    #[test]
    fn an_unknown_transcript_field_is_a_hard_parse_error() {
        let json = r#"{
            "journey_id": "j",
            "engine_version": 1,
            "steps": [],
            "bogus": 1
        }"#;
        let parsed: Result<JourneyTranscript, _> = serde_json::from_str(json);
        assert!(
            parsed.is_err(),
            "an unknown transcript field must be refused"
        );
    }

    #[test]
    fn a_transcript_that_sets_an_unpopulated_field_is_rejected_as_unfaithful() {
        // The engine's assemble_eval_context hardcodes empty groups and scopes (the sources
        // source_is_engine_live keeps not-live, issue #355), so a transcript that sets either would
        // replay against those ignored values yet drift from real behavior if the engine wired them.
        // The fidelity lint refuses each, naming the exact hop and field, and never panics. Risk IS
        // engine-live as of #355, so a transcript that sets it is allowed.
        let with_subject = |subject: TranscriptSubject| JourneyTranscript {
            journey_id: "login_conditional_mfa".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            description: None,
            steps: vec![TranscriptStep {
                comment: None,
                signals: TranscriptSignals::of([SignalName::PrimaryVerified]),
                subject: Some(subject),
                expect: ExpectedHop::Terminal("done".to_owned()),
            }],
        };
        // Groups set.
        assert_eq!(
            with_subject(TranscriptSubject {
                groups: BTreeSet::from(["staff".to_owned()]),
                ..TranscriptSubject::default()
            })
            .check_engine_faithful(),
            Err(UnfaithfulTranscript {
                step_index: 0,
                field: UnfaithfulField::Groups,
            })
        );
        // Scopes set.
        assert_eq!(
            with_subject(TranscriptSubject {
                scopes: BTreeSet::from(["read".to_owned()]),
                ..TranscriptSubject::default()
            })
            .check_engine_faithful(),
            Err(UnfaithfulTranscript {
                step_index: 0,
                field: UnfaithfulField::Scopes,
            })
        );
        // Risk set: engine-live as of issue #355, so it is allowed.
        assert_eq!(
            with_subject(TranscriptSubject {
                risk: Some(TranscriptRisk {
                    level: TranscriptRiskLevel::High,
                    score: 90,
                }),
                ..TranscriptSubject::default()
            })
            .check_engine_faithful(),
            Ok(())
        );
        // The engine-faithful subject fields (traits, method tokens, subject handle) are allowed.
        assert_eq!(
            with_subject(TranscriptSubject {
                traits: serde_json::json!({ "email_verified": true }),
                method_tokens: BTreeSet::from(["password".to_owned()]),
                subject_handle: "usr_abc".to_owned(),
                ..TranscriptSubject::default()
            })
            .check_engine_faithful(),
            Ok(())
        );
    }

    #[test]
    fn a_traits_routed_transcript_replays_faithfully() {
        // Traits ARE engine-faithful (assemble_eval_context reads the sealed trait document), so a
        // journey that routes on a subject_traits pointer replays truly. Verified staff go to a
        // review step; everyone else completes straight through.
        let journey = Journey {
            schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
            id: "traits_routed".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            entry: "primary".to_owned(),
            comment: None,
            steps: vec![
                step("primary", StepKind::IdentifierPassword, Some("password")),
                step("review", StepKind::MfaChallenge, Some("totp")),
                step("done", StepKind::Terminal, None),
            ],
            transitions: vec![
                Transition {
                    from: "primary".to_owned(),
                    to: "review".to_owned(),
                    guard: Some(Predicate::Cmp {
                        field: FieldRef {
                            source: FieldSource::SubjectTraits,
                            pointer: "/is_staff".to_owned(),
                        },
                        op: CmpOp::Eq,
                        value: Literal::Bool(true),
                    }),
                    comment: None,
                },
                Transition {
                    from: "primary".to_owned(),
                    to: "done".to_owned(),
                    guard: None,
                    comment: None,
                },
                Transition {
                    from: "review".to_owned(),
                    to: "done".to_owned(),
                    guard: None,
                    comment: None,
                },
            ],
            subflows: None,
            subflow_definitions: None,
        };
        let compiled = compile(&journey).expect("compiles");
        // A staff subject (the trait is true) threads the review step, then completes.
        let staff = JourneyTranscript {
            journey_id: "traits_routed".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            description: None,
            steps: vec![
                TranscriptStep {
                    comment: None,
                    signals: TranscriptSignals::of([SignalName::PrimaryVerified]),
                    subject: Some(TranscriptSubject {
                        traits: serde_json::json!({ "is_staff": true }),
                        ..TranscriptSubject::default()
                    }),
                    expect: ExpectedHop::Step("review".to_owned()),
                },
                TranscriptStep {
                    comment: None,
                    signals: TranscriptSignals::of([SignalName::PrimaryVerified]),
                    subject: None,
                    expect: ExpectedHop::Terminal("done".to_owned()),
                },
            ],
        };
        assert!(staff.check_engine_faithful().is_ok());
        assert_eq!(run(&compiled, &staff), ReplayReport::Match);
        // A non-staff subject (the trait is absent) completes straight from the primary step.
        let other = JourneyTranscript {
            journey_id: "traits_routed".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            description: None,
            steps: vec![TranscriptStep {
                comment: None,
                signals: TranscriptSignals::of([SignalName::PrimaryVerified]),
                subject: None,
                expect: ExpectedHop::Terminal("done".to_owned()),
            }],
        };
        assert_eq!(run(&compiled, &other), ReplayReport::Match);
    }

    #[test]
    fn a_risk_routed_transcript_replays_against_the_real_risk() {
        // Risk `/level` is engine-live as of issue #355, so a journey routing on it replays against
        // the transcript's real risk. A High verdict threads the review step; a Low (or absent)
        // risk completes straight through.
        let journey = Journey {
            schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
            id: "risk_routed".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            entry: "primary".to_owned(),
            comment: None,
            steps: vec![
                step("primary", StepKind::IdentifierPassword, Some("password")),
                step("review", StepKind::MfaChallenge, Some("totp")),
                step("done", StepKind::Terminal, None),
            ],
            transitions: vec![
                Transition {
                    from: "primary".to_owned(),
                    to: "review".to_owned(),
                    guard: Some(Predicate::Cmp {
                        field: FieldRef {
                            source: FieldSource::Risk,
                            pointer: "/level".to_owned(),
                        },
                        op: CmpOp::Eq,
                        value: Literal::String("high".to_owned()),
                    }),
                    comment: None,
                },
                Transition {
                    from: "primary".to_owned(),
                    to: "done".to_owned(),
                    guard: None,
                    comment: None,
                },
                Transition {
                    from: "review".to_owned(),
                    to: "done".to_owned(),
                    guard: None,
                    comment: None,
                },
            ],
            subflows: None,
            subflow_definitions: None,
        };
        let compiled = compile(&journey).expect("compiles");
        // A High-risk subject threads the review step, then completes.
        let high = JourneyTranscript {
            journey_id: "risk_routed".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            description: None,
            steps: vec![
                TranscriptStep {
                    comment: None,
                    signals: TranscriptSignals::of([SignalName::PrimaryVerified]),
                    subject: Some(TranscriptSubject {
                        risk: Some(TranscriptRisk {
                            level: TranscriptRiskLevel::High,
                            score: 0,
                        }),
                        ..TranscriptSubject::default()
                    }),
                    expect: ExpectedHop::Step("review".to_owned()),
                },
                TranscriptStep {
                    comment: None,
                    signals: TranscriptSignals::of([SignalName::PrimaryVerified]),
                    subject: None,
                    expect: ExpectedHop::Terminal("done".to_owned()),
                },
            ],
        };
        assert!(high.check_engine_faithful().is_ok());
        assert_eq!(run(&compiled, &high), ReplayReport::Match);
        // A Low-risk subject (risk absent, the engine's default Low) completes straight through.
        let low = JourneyTranscript {
            journey_id: "risk_routed".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            description: None,
            steps: vec![TranscriptStep {
                comment: None,
                signals: TranscriptSignals::of([SignalName::PrimaryVerified]),
                subject: None,
                expect: ExpectedHop::Terminal("done".to_owned()),
            }],
        };
        assert!(low.check_engine_faithful().is_ok());
        assert_eq!(run(&compiled, &low), ReplayReport::Match);
    }
}
