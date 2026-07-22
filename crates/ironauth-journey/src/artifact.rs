// SPDX-License-Identifier: MIT OR Apache-2.0

//! The journey artifact value model (issue #92, PR 1): the serde structs that (de)serialize
//! to and from the canonical JSON document, plus the predicate AST expressed as DATA. Pure
//! value types only; the load-time validator lives in [`crate::validate`] and the derived
//! JSON Schema in [`crate::schema`].

use std::borrow::Cow;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::Deserializer;
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

/// The orchestration ABI version this crate supports: the [`StepKind`] vocabulary, the
/// predicate grammar, and the node-group set. An artifact declares the engine version it was
/// authored for, and the validator refuses one that declares a version newer than this
/// (see [`crate::JourneyError::EngineIncompatible`]). It is DISTINCT from the rendered flow
/// contract version: the artifact compiles down to the engine's table, it never renders as a
/// flow object directly.
///
/// Bumped to 2 for issue #92 (PR 8a, engine convergence): the [`StepKind`] vocabulary gains the
/// three BUILT-IN-ONLY mint-family kinds ([`StepKind::Registration`],
/// [`StepKind::RecoveryStart`], [`StepKind::RecoveryVerify`]) the embedded built-in journeys
/// converge onto. The addition is purely ADDITIVE: the compatibility check refuses only an
/// artifact declaring a version GREATER than this, so a version-1 artifact (which cannot name any
/// of the new kinds) still loads unchanged. The rendered flow contract version is independent and
/// unaffected.
pub const JOURNEY_ENGINE_VERSION: u32 = 2;

/// The stable artifact format tag every journey document carries in its `schema_version`
/// field. It names the on-the-wire shape (the JSON canonical form), independent of the
/// orchestration ABI in [`JOURNEY_ENGINE_VERSION`].
pub const JOURNEY_SCHEMA_VERSION: &str = "ironauth.journey/v1";

/// The identifier of a step within a journey (a document-local name, unique across the
/// journey's steps).
pub type StepId = String;

/// The identifier of a subflow reference within a journey (a document-local name).
pub type SubflowId = String;

/// A whole journey artifact (issue #92): the declarative topology and routing a flow runs.
/// It carries the format tag, the authored engine version, the entry step, the step list,
/// the transitions between steps, and any subflow references. Comments are FIRST-CLASS data
/// fields, preserved through a serde round-trip, never lexical trivia.
///
/// An unknown or misspelled property is a HARD parse error (`deny_unknown_fields`), so a typo
/// like `gaurd` cannot silently drop a guard and change routing; the published schema mirrors
/// this with `additionalProperties: false`.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Journey {
    /// The artifact format tag; the canonical value is [`JOURNEY_SCHEMA_VERSION`].
    pub schema_version: String,
    /// The document-local journey identifier.
    pub id: String,
    /// The orchestration ABI version this artifact was authored for; the validator refuses a
    /// value greater than [`JOURNEY_ENGINE_VERSION`].
    pub engine_version: u32,
    /// The entry step: the step id the journey starts at.
    pub entry: StepId,
    /// An optional human-readable comment about the journey (data, round-trip-safe).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// The steps this journey can occupy, in document order.
    pub steps: Vec<Step>,
    /// The transitions between steps, in document order.
    pub transitions: Vec<Transition>,
    /// The subflow references this journey can call, or [`None`] when it calls none. Each
    /// reference maps a document-local alias id to its source (a built-in subflow or an inline
    /// definition), and a [`StepKind::SubflowCall`] step names the alias.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subflows: Option<Vec<SubflowRef>>,
    /// The inline subflow DEFINITIONS this artifact carries (issue #92, PR 3), or [`None`] when it
    /// carries none. A [`SubflowRef`] with an [`SubflowSource::Inline`] source resolves to the
    /// definition here whose `id` matches its `subflow_id`. Distinct from the `subflows` REFERENCE
    /// list: `subflows` declares which subflows a journey uses (alias plus source), while
    /// `subflow_definitions` carries the reusable fragment bodies themselves. A single definition
    /// is a shared, id-resolved fragment: two journeys that reference the same definition compile
    /// against the same body (edit-once-both-change), with version pinning layered on in a later PR.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subflow_definitions: Option<Vec<Subflow>>,
}

/// A reusable sub-flow fragment (issue #92, PR 3): a mini-journey the composition step splices
/// into a calling journey (the inner-tree analog). It mirrors the [`Journey`] shape but is NOT a
/// standalone flow: it has an entry, a set of steps and transitions, and one or more RETURN
/// points (its `exits`). A subflow never mints a session; it always RETURNS to its caller, so a
/// subflow declares no terminal step (a [`StepKind::Terminal`] inside a subflow is a load-time
/// error). Its steps and transitions are validated with the SAME structural rules as a journey's
/// (vocabulary, reachability, dead-end, kind and attachment coherence, predicate type-check),
/// except that the `exits` play the completion role a journey's terminal steps play.
///
/// ## Composition and return semantics
///
/// A [`StepKind::SubflowCall`] step names a subflow. On composition the subflow's fragment is
/// spliced into the journey: the transitions that targeted the call step are redirected to the
/// subflow's `entry`, and each of the call step's OUTGOING transitions (the RETURN edges) is
/// grafted onto every one of the subflow's `exits`, so control flows into the subflow at its
/// entry and returns to the caller from its exits. Each exit is a leaf step (no outgoing
/// transition within the subflow); its own kind executor runs, and on completion routing follows
/// the caller's return edges. Composition is a pure, load-time splice: it never runs at flow time.
///
/// An unknown property is a hard parse error (`deny_unknown_fields`).
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Subflow {
    /// The subflow definition id (the key an inline [`SubflowSource::Inline`] reference and a
    /// nested [`StepKind::SubflowCall`] resolve against). Unique across the artifact's inline
    /// definitions and distinct from every built-in subflow name.
    pub id: SubflowId,
    /// The entry step: the step id control enters the subflow at.
    pub entry: StepId,
    /// The return points: the step ids control returns to the caller from. Each must name a
    /// declared step that is a leaf (no outgoing transition within the subflow) and is not a
    /// terminal. A subflow declares at least one exit.
    pub exits: Vec<StepId>,
    /// An optional human-readable comment about the subflow (data, round-trip-safe).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// The steps this subflow can occupy, in document order (the same shape as a journey's steps).
    pub steps: Vec<Step>,
    /// The transitions between the subflow's steps, in document order.
    pub transitions: Vec<Transition>,
}

/// One step of a journey (issue #92): a document-local id, the built-in kind that executes
/// it, and the kind-specific attachments (the node group it renders under, the subflow it
/// calls, or the decision it evaluates). Comments are data fields. An unknown property is a
/// hard parse error (`deny_unknown_fields`).
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Step {
    /// The document-local step id (unique across the journey's steps).
    pub id: StepId,
    /// The built-in step kind that executes this step.
    pub kind: StepKind,
    /// The node group this step renders under, when the kind renders a UI (validated against
    /// the existing node-group vocabulary; see [`crate::NODE_GROUPS`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_group: Option<String>,
    /// The subflow this step calls, for a [`StepKind::SubflowCall`] step (a reference into the
    /// journey's `subflows` list).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subflow: Option<SubflowId>,
    /// The decision predicate carried by a [`StepKind::Decision`] step. It is validated and type
    /// checked at load, but the built-in engine routes a decision step through its guarded
    /// transitions, not this attachment, which is reserved for a future outcome-based routing mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<DecisionSpec>,
    /// An optional human-readable comment about the step (data, round-trip-safe).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// The built-in step kinds a journey step may declare (issue #92): the CLOSED orchestration
/// vocabulary, mirroring the engine's flow-state and step vocabulary. Each known kind names a
/// fixed Rust executor; the artifact never expresses step-internal logic. The wire form is
/// the `snake_case` tag.
///
/// The [`StepKind::Unknown`] variant is NOT a built-in kind: it is the parse-tolerant carrier
/// for an unrecognized wire value, so the load-time validator rejects it with
/// [`crate::JourneyError::UnknownStepKind`] (carrying the offending name) rather than failing
/// the parse opaquely. The published JSON Schema lists ONLY the closed built-in set, so a
/// schema-level check still rejects an unknown kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepKind {
    /// The login identifier plus password first factor.
    IdentifierPassword,
    /// A second factor challenge.
    MfaChallenge,
    /// A second factor enrollment.
    MfaEnroll,
    /// A progressive-profiling step that collects held later-login fields.
    ProgressiveProfiling,
    /// A pure routing hub: it renders nothing and runs no executor, and the engine routes
    /// onward through this step's own guarded transitions (the transition guards carry the
    /// branching predicates). The step's `decision` attachment is a reserved slot for a future
    /// outcome-based routing mode (the M11 sandbox seam) and is not consulted by the built-in
    /// edge-guard routing.
    Decision,
    /// A call into a subflow named by the step's `subflow` reference.
    SubflowCall,
    /// A terminal step: the journey leaves it only by completing.
    Terminal,
    /// The registration details (identifier plus password) first factor that CREATES an account
    /// and mints the first session (issue #92, PR 8a). A BUILT-IN-ONLY kind: it may appear only in
    /// an embedded built-in artifact, never a custom-authored one (see [`StepKind::is_builtin_only`]),
    /// because it creates accounts and mints sessions. It wraps the existing
    /// `registration::advance_registration` primitive.
    Registration,
    /// The recovery identifier entry that initiates account recovery (issue #92, PR 8a): the
    /// anti-enumeration start step that delivers the one-time code uniformly. A BUILT-IN-ONLY kind
    /// (it drives a session-minting recovery), it routes to [`StepKind::RecoveryVerify`] by an
    /// UNCONDITIONAL edge, so it introduces no new outcome signal. It wraps
    /// `recovery::advance_start`.
    RecoveryStart,
    /// The recovery one-time-code verification that mints the session on a genuine proof (issue
    /// #92, PR 8a): the uniform acknowledgment plus code entry. A BUILT-IN-ONLY kind (it mints a
    /// session and runs the post-mint counter reset), it wraps `recovery::advance_verify`.
    RecoveryVerify,
    /// Not a built-in kind: an unrecognized wire value, preserved so the load-time validator
    /// can reject it cleanly. Carries the offending kind string.
    Unknown(String),
}

impl StepKind {
    /// The ten built-in kind wire strings, in declaration order. This is the closed set the
    /// published JSON Schema enumerates and the load-time validator accepts. The three
    /// mint-family kinds ([`StepKind::Registration`], [`StepKind::RecoveryStart`],
    /// [`StepKind::RecoveryVerify`]) are BUILT-IN-ONLY (see [`StepKind::is_builtin_only`]).
    pub const BUILT_IN: [&'static str; 10] = [
        "identifier_password",
        "mfa_challenge",
        "mfa_enroll",
        "progressive_profiling",
        "decision",
        "subflow_call",
        "terminal",
        "registration",
        "recovery_start",
        "recovery_verify",
    ];

    /// The wire string for this kind. For [`StepKind::Unknown`] it is the offending value the
    /// parser preserved.
    #[must_use]
    pub fn as_wire(&self) -> &str {
        match self {
            StepKind::IdentifierPassword => "identifier_password",
            StepKind::MfaChallenge => "mfa_challenge",
            StepKind::MfaEnroll => "mfa_enroll",
            StepKind::ProgressiveProfiling => "progressive_profiling",
            StepKind::Decision => "decision",
            StepKind::SubflowCall => "subflow_call",
            StepKind::Terminal => "terminal",
            StepKind::Registration => "registration",
            StepKind::RecoveryStart => "recovery_start",
            StepKind::RecoveryVerify => "recovery_verify",
            StepKind::Unknown(raw) => raw.as_str(),
        }
    }

    /// Parse a wire string into a kind, mapping any unrecognized value to
    /// [`StepKind::Unknown`] so the load-time validator can reject it with a pointer.
    #[must_use]
    pub fn from_wire(raw: &str) -> Self {
        match raw {
            "identifier_password" => StepKind::IdentifierPassword,
            "mfa_challenge" => StepKind::MfaChallenge,
            "mfa_enroll" => StepKind::MfaEnroll,
            "progressive_profiling" => StepKind::ProgressiveProfiling,
            "decision" => StepKind::Decision,
            "subflow_call" => StepKind::SubflowCall,
            "terminal" => StepKind::Terminal,
            "registration" => StepKind::Registration,
            "recovery_start" => StepKind::RecoveryStart,
            "recovery_verify" => StepKind::RecoveryVerify,
            other => StepKind::Unknown(other.to_owned()),
        }
    }

    /// Whether this is one of the closed built-in kinds (not [`StepKind::Unknown`]).
    #[must_use]
    pub fn is_known(&self) -> bool {
        !matches!(self, StepKind::Unknown(_))
    }

    /// Whether this kind may appear ONLY in an EMBEDDED built-in artifact, never a custom-authored
    /// one (issue #92, PR 8a). The three mint-family kinds ([`StepKind::Registration`],
    /// [`StepKind::RecoveryStart`], [`StepKind::RecoveryVerify`]) CREATE accounts or MINT sessions
    /// through fixed built-in ceremonies, so a custom author must not be able to name them (a
    /// custom journey cannot mint an arbitrary account or session): the load-time validator refuses
    /// one in a custom artifact with [`crate::JourneyError::BuiltinOnlyStepKind`], while
    /// [`crate::compile_builtin`] admits them for the embedded built-in journeys that converge onto
    /// the compiled table.
    ///
    /// The pre-existing kinds ([`StepKind::IdentifierPassword`], the MFA kinds, and
    /// [`StepKind::ProgressiveProfiling`]) STAY custom-usable exactly as before: although
    /// `identifier_password` and the MFA kinds also prove factors, they authenticate an EXISTING
    /// subject the primary factor established and never create an account, and the AC1 custom
    /// fixture composes them, so they are not built-in-only. Only the account-creating and
    /// recovery-minting kinds are gated.
    #[must_use]
    pub fn is_builtin_only(&self) -> bool {
        matches!(
            self,
            StepKind::Registration | StepKind::RecoveryStart | StepKind::RecoveryVerify
        )
    }

    /// Whether this is the terminal kind (a step the journey leaves only by completing).
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, StepKind::Terminal)
    }
}

impl Serialize for StepKind {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_wire())
    }
}

impl<'de> Deserialize<'de> for StepKind {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Ok(StepKind::from_wire(&raw))
    }
}

impl JsonSchema for StepKind {
    fn schema_name() -> Cow<'static, str> {
        "StepKind".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::StepKind").into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        // Only the closed built-in set is published, so a schema-level check rejects an unknown
        // kind even though the Rust parse is tolerant (to yield a validator error with a pointer).
        json_schema!({
            "type": "string",
            "enum": StepKind::BUILT_IN,
            "description": "A built-in journey step kind (the closed orchestration vocabulary).",
        })
    }
}

/// A transition between two steps (issue #92): the source step, the target step, and an
/// optional guard predicate that must hold for the transition to be taken. An UNGUARDED
/// transition (a `guard` of [`None`]) always applies; two or more unguarded transitions from
/// the same step are ambiguous and the validator rejects them
/// ([`crate::JourneyError::NonDeterministicTransition`]). An unknown property (a misspelled
/// `guard`, for example) is a hard parse error (`deny_unknown_fields`), so it can never
/// silently drop the guard and change routing.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Transition {
    /// The source step id.
    pub from: StepId,
    /// The target step id.
    pub to: StepId,
    /// The guard predicate, or [`None`] for an unguarded (always-applicable) transition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guard: Option<Predicate>,
    /// An optional human-readable comment about the transition (data, round-trip-safe).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// A subflow reference a journey can call (issue #92): a document-local id and its source. PR
/// 1 parses and validates the SHAPE only; full subflow composition is PR 3. An unknown
/// property is a hard parse error (`deny_unknown_fields`).
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SubflowRef {
    /// The document-local subflow id a [`StepKind::SubflowCall`] step references.
    pub id: SubflowId,
    /// Where the subflow's definition comes from.
    pub source: SubflowSource,
}

/// The source of a subflow reference (issue #92). Kept minimal for PR 1: a built-in subflow
/// the engine provides, or an inline reference by id (full inline composition is PR 3). Tagged
/// by `kind` on the wire.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SubflowSource {
    /// A built-in subflow the engine provides, named (for example `mfa_step_up`).
    Builtin {
        /// The built-in subflow name.
        name: String,
    },
    /// An inline subflow referenced by id; the inline body lands in PR 3.
    Inline {
        /// The referenced inline subflow id.
        subflow_id: SubflowId,
    },
}

/// A decision a branch step evaluates (issue #92). Modeled as an enum so a later milestone can
/// add an alternative (a sandboxed evaluator) without a breaking shape change; PR 1 reserves
/// the shape and defines only the predicate form. Tagged by `type` on the wire.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DecisionSpec {
    /// A decision expressed as a predicate over the typed evaluation context.
    Predicate {
        /// The predicate this decision evaluates.
        predicate: Predicate,
    },
}

/// The predicate AST (issue #92): a minimal, closed grammar over comparisons, membership, and
/// boolean combinators, expressed as DATA. PR 1 defines it and validates its STRUCTURE (the
/// serde shape); it does NOT evaluate it and does NOT unify its types. The evaluator and the
/// load-time type check are PR 2. Tagged by `type` on the wire.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Predicate {
    /// A comparison of a field against a literal under a comparison operator.
    Cmp {
        /// The field being compared.
        field: FieldRef,
        /// The comparison operator.
        op: CmpOp,
        /// The literal the field is compared against.
        value: Literal,
    },
    /// Whether a field's value is one of a closed set of literals.
    In {
        /// The field being tested.
        field: FieldRef,
        /// The permitted literals.
        values: Vec<Literal>,
    },
    /// Whether the subject is a member of a named group or scope set.
    Member {
        /// The field the membership is read from.
        field: FieldRef,
        /// The set the subject is tested against.
        set: MemberSet,
    },
    /// A conjunction: every operand must hold.
    And {
        /// The operands, all of which must hold.
        operands: Vec<Predicate>,
    },
    /// A disjunction: at least one operand must hold.
    Or {
        /// The operands, at least one of which must hold.
        operands: Vec<Predicate>,
    },
    /// A negation of a single operand.
    Not {
        /// The operand being negated.
        operand: Box<Predicate>,
    },
    /// The constant true predicate.
    Always,
    /// The constant false predicate.
    Never,
}

/// A comparison operator (issue #92): the closed set of ordering and equality operators the
/// predicate grammar permits. The wire form is the `snake_case` tag.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CmpOp {
    /// Equal.
    Eq,
    /// Not equal.
    Ne,
    /// Less than.
    Lt,
    /// Less than or equal.
    Le,
    /// Greater than.
    Gt,
    /// Greater than or equal.
    Ge,
}

/// A typed reference to a field of the evaluation context (issue #92): the source it is read
/// from and an RFC 6901 JSON Pointer into that source. The evaluation context is assembled by
/// the engine before the predicate is evaluated (PR 2); PR 1 defines the reference as data. An
/// unknown property is a hard parse error (`deny_unknown_fields`).
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FieldRef {
    /// The context source this field is read from.
    pub source: FieldSource,
    /// The RFC 6901 JSON Pointer into the source.
    pub pointer: String,
}

/// The typed sources a [`FieldRef`] can read from (issue #92): a closed set. Flow-local state,
/// step outcome signals, the subject's sealed traits, the subject's groups and scopes, and the
/// risk decision. The wire form is the `snake_case` tag.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FieldSource {
    /// Flow-local state (the step id, the proven method tokens).
    Flow,
    /// Step outcome signals (for example `mfa_required`, `primary_verified`).
    Signals,
    /// The subject's sealed identity traits.
    SubjectTraits,
    /// The subject's group memberships.
    SubjectGroups,
    /// The subject's granted scopes.
    SubjectScopes,
    /// The risk decision.
    Risk,
}

/// The set a [`Predicate::Member`] tests the subject against (issue #92): a named group or a
/// named scope. Tagged by `kind` on the wire.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MemberSet {
    /// A named subject group.
    Group {
        /// The group name.
        name: String,
    },
    /// A named subject scope.
    Scope {
        /// The scope name.
        name: String,
    },
}

/// A literal value in the predicate grammar (issue #92): the CLOSED set of primitive JSON
/// values a comparison or membership test permits. An object or an array is NOT a literal. The
/// wire form is the bare JSON value (untagged).
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum Literal {
    /// A JSON null.
    Null,
    /// A boolean.
    Bool(bool),
    /// A number.
    Number(serde_json::Number),
    /// A string.
    String(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A realistic identifier-first-with-conditional-MFA journey, exercised by the round-trip
    /// test here and reused as the valid fixture by the validator tests.
    pub(crate) fn conditional_mfa_journey() -> Journey {
        Journey {
            schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
            id: "login_conditional_mfa".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            entry: "primary".to_owned(),
            comment: Some("Identifier plus password, then MFA only when required.".to_owned()),
            steps: vec![
                Step {
                    id: "primary".to_owned(),
                    kind: StepKind::IdentifierPassword,
                    node_group: Some("password".to_owned()),
                    subflow: None,
                    decision: None,
                    comment: Some("The first factor.".to_owned()),
                },
                Step {
                    id: "mfa".to_owned(),
                    kind: StepKind::MfaChallenge,
                    node_group: Some("totp".to_owned()),
                    subflow: None,
                    decision: None,
                    comment: None,
                },
                Step {
                    id: "done".to_owned(),
                    kind: StepKind::Terminal,
                    node_group: None,
                    subflow: None,
                    decision: None,
                    comment: Some("Session minted.".to_owned()),
                },
            ],
            transitions: vec![
                Transition {
                    from: "primary".to_owned(),
                    to: "mfa".to_owned(),
                    guard: Some(Predicate::Cmp {
                        field: FieldRef {
                            source: FieldSource::Signals,
                            pointer: "/mfa_required".to_owned(),
                        },
                        op: CmpOp::Eq,
                        value: Literal::Bool(true),
                    }),
                    comment: Some("Step up only when a second factor is required.".to_owned()),
                },
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
    fn a_journey_with_comments_round_trips_identically() {
        let journey = conditional_mfa_journey();
        let json = serde_json::to_string(&journey).expect("serialize");
        let parsed: Journey = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, journey);
        // Comments are preserved as data through the round-trip.
        assert_eq!(
            parsed.comment.as_deref(),
            Some("Identifier plus password, then MFA only when required.")
        );
        assert_eq!(
            parsed.steps[0].comment.as_deref(),
            Some("The first factor.")
        );
        assert_eq!(
            parsed.transitions[0].comment.as_deref(),
            Some("Step up only when a second factor is required.")
        );
        // The step kind serializes to its snake_case wire form.
        assert!(json.contains("\"identifier_password\""));
    }

    #[test]
    fn the_step_kind_wire_form_is_the_closed_snake_case_set() {
        for wire in StepKind::BUILT_IN {
            let kind = StepKind::from_wire(wire);
            assert!(kind.is_known());
            assert_eq!(kind.as_wire(), wire);
            // The wire form round-trips through serde as a bare string.
            let json = serde_json::to_string(&kind).expect("serialize");
            assert_eq!(json, format!("\"{wire}\""));
            let back: StepKind = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, kind);
        }
        // An unrecognized value parses tolerantly into Unknown, carrying the offending name.
        let unknown: StepKind = serde_json::from_str("\"teleport\"").expect("deserialize");
        assert_eq!(unknown, StepKind::Unknown("teleport".to_owned()));
        assert!(!unknown.is_known());
    }

    #[test]
    fn the_three_mint_family_kinds_are_built_in_only() {
        // The new PR 8a kinds are BUILT-IN-ONLY: they create accounts or mint recovery sessions.
        for wire in ["registration", "recovery_start", "recovery_verify"] {
            let kind = StepKind::from_wire(wire);
            assert!(kind.is_known(), "{wire} is a known built-in kind");
            assert!(kind.is_builtin_only(), "{wire} is built-in-only");
            assert!(
                StepKind::BUILT_IN.contains(&wire),
                "{wire} is in the closed built-in set"
            );
        }
        // The pre-existing kinds stay custom-usable (not built-in-only), including the ones that
        // prove factors for an already-established subject.
        for wire in [
            "identifier_password",
            "mfa_challenge",
            "mfa_enroll",
            "progressive_profiling",
            "decision",
            "subflow_call",
            "terminal",
        ] {
            assert!(
                !StepKind::from_wire(wire).is_builtin_only(),
                "{wire} stays custom-usable"
            );
        }
        // The closed built-in set grew from seven to ten.
        assert_eq!(StepKind::BUILT_IN.len(), 10);
    }

    #[test]
    fn the_predicate_ast_round_trips_through_json() {
        let predicate = Predicate::And {
            operands: vec![
                Predicate::Cmp {
                    field: FieldRef {
                        source: FieldSource::SubjectTraits,
                        pointer: "/email_verified".to_owned(),
                    },
                    op: CmpOp::Eq,
                    value: Literal::Bool(true),
                },
                Predicate::Or {
                    operands: vec![
                        Predicate::In {
                            field: FieldRef {
                                source: FieldSource::Risk,
                                pointer: "/level".to_owned(),
                            },
                            values: vec![
                                Literal::String("low".to_owned()),
                                Literal::String("medium".to_owned()),
                            ],
                        },
                        Predicate::Member {
                            field: FieldRef {
                                source: FieldSource::SubjectGroups,
                                pointer: String::new(),
                            },
                            set: MemberSet::Group {
                                name: "staff".to_owned(),
                            },
                        },
                        Predicate::Not {
                            operand: Box::new(Predicate::Never),
                        },
                    ],
                },
                Predicate::Always,
            ],
        };
        let json = serde_json::to_string(&predicate).expect("serialize");
        let parsed: Predicate = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, predicate);
    }

    #[test]
    fn every_literal_kind_round_trips() {
        for literal in [
            Literal::Null,
            Literal::Bool(true),
            Literal::Number(serde_json::Number::from(7)),
            Literal::String("hello".to_owned()),
        ] {
            let json = serde_json::to_string(&literal).expect("serialize");
            let parsed: Literal = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(parsed, literal);
        }
    }

    #[test]
    fn an_unknown_field_on_the_journey_is_a_hard_parse_error() {
        // deny_unknown_fields: an extra top-level property is refused rather than dropped.
        let json = serde_json::to_string(&conditional_mfa_journey()).expect("serialize");
        let mut document: serde_json::Value = serde_json::from_str(&json).expect("value");
        document
            .as_object_mut()
            .expect("object")
            .insert("bogus".to_owned(), serde_json::json!(1));
        let parsed: Result<Journey, _> = serde_json::from_value(document);
        assert!(parsed.is_err(), "an unknown journey field must be refused");
    }

    #[test]
    fn a_misspelled_guard_on_a_transition_is_a_hard_parse_error() {
        // A typo like `gaurd` would otherwise parse, drop the guard, and silently make the
        // transition unguarded (changing routing). deny_unknown_fields refuses it instead.
        let json = r#"{
            "schema_version": "ironauth.journey/v1",
            "id": "j",
            "engine_version": 1,
            "entry": "primary",
            "steps": [
                {"id": "primary", "kind": "identifier_password"},
                {"id": "done", "kind": "terminal"}
            ],
            "transitions": [
                {"from": "primary", "to": "done", "gaurd": {"type": "always"}}
            ]
        }"#;
        let parsed: Result<Journey, _> = serde_json::from_str(json);
        assert!(
            parsed.is_err(),
            "a misspelled guard field must be refused, never silently dropped"
        );
    }
}
