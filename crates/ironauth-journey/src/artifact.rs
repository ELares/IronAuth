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
pub const JOURNEY_ENGINE_VERSION: u32 = 1;

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
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
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
    /// The subflow references this journey can call, or [`None`] when it calls none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subflows: Option<Vec<SubflowRef>>,
}

/// One step of a journey (issue #92): a document-local id, the built-in kind that executes
/// it, and the kind-specific attachments (the node group it renders under, the subflow it
/// calls, or the decision it evaluates). Comments are data fields.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
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
    /// The decision this step evaluates, for a [`StepKind::Decision`] step.
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
    /// A branch step: evaluate a decision and route on its outcome.
    Decision,
    /// A call into a subflow named by the step's `subflow` reference.
    SubflowCall,
    /// A terminal step: the journey leaves it only by completing.
    Terminal,
    /// Not a built-in kind: an unrecognized wire value, preserved so the load-time validator
    /// can reject it cleanly. Carries the offending kind string.
    Unknown(String),
}

impl StepKind {
    /// The seven built-in kind wire strings, in declaration order. This is the closed set the
    /// published JSON Schema enumerates and the load-time validator accepts.
    pub const BUILT_IN: [&'static str; 7] = [
        "identifier_password",
        "mfa_challenge",
        "mfa_enroll",
        "progressive_profiling",
        "decision",
        "subflow_call",
        "terminal",
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
            other => StepKind::Unknown(other.to_owned()),
        }
    }

    /// Whether this is one of the closed built-in kinds (not [`StepKind::Unknown`]).
    #[must_use]
    pub fn is_known(&self) -> bool {
        !matches!(self, StepKind::Unknown(_))
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
/// ([`crate::JourneyError::NonDeterministicTransition`]).
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
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
/// 1 parses and validates the SHAPE only; full subflow composition is PR 3.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
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
/// the engine before the predicate is evaluated (PR 2); PR 1 defines the reference as data.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
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
}
