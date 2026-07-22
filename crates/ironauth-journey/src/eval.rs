// SPDX-License-Identifier: MIT OR Apache-2.0

//! The decision-node predicate EVALUATOR (issue #92, PR 2): the typed evaluation context the
//! evaluator reads, the pure `evaluate` over the PR 1 predicate AST, and the load-time predicate
//! type check that guarantees the evaluator only ever runs type-safe predicates.
//!
//! ## Purity discipline
//!
//! The evaluator is PURE, mirroring the identity-traits schema layer
//! (`ironauth_store::trait_schema`): it has NO clock, NO entropy, and NO I/O. Any time-based
//! routing need is pre-evaluated by the engine into a boolean outcome signal BEFORE the
//! evaluation context is assembled, so the evaluator never sees a clock. Evaluation is
//! DETERMINISTIC and TOTAL: the same predicate and context always yield the same result, and no
//! admitted input panics. Recursion is DEPTH-BOUNDED by [`MAX_PREDICATE_DEPTH`] (mirroring
//! `trait_schema::MAX_DEPTH`) so a pathologically nested predicate cannot exhaust the stack.
//!
//! ## The typed context is a SHAPE only here
//!
//! PR 2 defines the [`EvalContext`] SHAPE (the typed fields the evaluator reads) and provides
//! test constructors only. POPULATING it from real flow state (the engine's outcome signals, the
//! sealed trait document, the subject's groups and scopes, the risk decision) is PR 4; this crate
//! stays a pure library with no engine, database, or endpoint.
//!
//! ## The M11 sandbox seam
//!
//! [`DecisionEvaluator`] is the one seam a later milestone (M11) extends with a sandboxed
//! evaluator, ALONGSIDE the built-in predicate, never gating it. PR 2 ships only the built-in
//! predicate impl; see the trait's documentation.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt;

use serde_json::{Number, Value};

use crate::artifact::{CmpOp, DecisionSpec, FieldRef, FieldSource, Literal, MemberSet, Predicate};

/// The maximum predicate nesting depth the evaluator and the load-time type check admit (issue
/// #92), mirroring `ironauth_store::trait_schema::MAX_DEPTH`. A predicate nested deeper is
/// rejected at load ([`PredicateTypeError`]) and, as defense in depth, refused at evaluation
/// ([`PredicateError::TooDeep`]) rather than recursing far enough to exhaust the stack. The
/// entry predicate is depth zero.
pub const MAX_PREDICATE_DEPTH: usize = 32;

/// The typed evaluation context a predicate reads (issue #92): the closed set of sources the
/// grammar's [`FieldSource`] selects. It is assembled by the engine BEFORE evaluation (so all
/// I/O happens at assembly and the evaluator itself is pure); PR 2 defines the SHAPE and provides
/// test constructors, and PR 4 populates it from real flow state.
///
/// Construct one with [`EvalContext::default`] (an empty context: no signals, no groups, no
/// scopes, a null trait document, and the lowest risk) and set the fields a test needs, or build
/// the parts with [`FlowContext`], [`SignalSet`], and [`RiskView`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EvalContext {
    /// Flow-local state: the current step, the proven method tokens, the blind subject handle,
    /// and the step outcome signals.
    pub flow: FlowContext,
    /// The subject's sealed identity trait document (the #53 trait doc), a read-only JSON value
    /// addressed by an RFC 6901 JSON Pointer. An absent optional trait resolves to JSON null.
    pub subject_traits: Value,
    /// The subject's group memberships (a [`Predicate::Member`] with a group set tests against
    /// this).
    pub subject_groups: BTreeSet<String>,
    /// The subject's granted scopes (a [`Predicate::Member`] with a scope set tests against this).
    pub subject_scopes: BTreeSet<String>,
    /// The risk decision view the flow exposes.
    pub risk: RiskView,
}

impl EvalContext {
    /// Resolve a field reference to a scalar for a comparison or membership test. A source that is
    /// a set, an array, or an object (never a scalar) resolves to [`Resolution::NonScalar`]; an
    /// absent optional trait resolves to [`Resolution::Scalar`] of [`ResolvedScalar::Null`]. An
    /// unknown pointer into a closed source resolves benignly to null (the load-time type check
    /// already rejects it, so this only keeps evaluation total).
    fn resolve_scalar(&self, field: &FieldRef) -> Resolution {
        match field.source {
            FieldSource::Flow => match field.pointer.as_str() {
                "/step_id" => Resolution::Scalar(ResolvedScalar::Str(self.flow.step_id.clone())),
                "/subject" => {
                    Resolution::Scalar(ResolvedScalar::Str(self.flow.subject_handle.clone()))
                }
                "/method_tokens" => Resolution::NonScalar,
                _ => Resolution::Scalar(ResolvedScalar::Null),
            },
            FieldSource::Signals => match signal_from_pointer(&field.pointer) {
                Some(signal) => {
                    Resolution::Scalar(ResolvedScalar::Bool(self.flow.signals.asserted(signal)))
                }
                None => Resolution::Scalar(ResolvedScalar::Null),
            },
            FieldSource::SubjectTraits => match self.subject_traits.pointer(&field.pointer) {
                Some(value) => value_to_resolution(value),
                // An absent optional trait is JSON null (the documented total rule).
                None => Resolution::Scalar(ResolvedScalar::Null),
            },
            // The whole group or scope set is not a scalar; it is tested by membership, never
            // compared.
            FieldSource::SubjectGroups | FieldSource::SubjectScopes => Resolution::NonScalar,
            FieldSource::Risk => match field.pointer.as_str() {
                "/level" => {
                    Resolution::Scalar(ResolvedScalar::Str(self.risk.level.as_wire().to_owned()))
                }
                "/score" => {
                    Resolution::Scalar(ResolvedScalar::Number(Number::from(self.risk.score)))
                }
                _ => Resolution::Scalar(ResolvedScalar::Null),
            },
        }
    }
}

/// Flow-local evaluation state (issue #92): the SHAPE the engine populates in PR 4.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FlowContext {
    /// The current step id (readable as the flow source pointer `/step_id`).
    pub step_id: String,
    /// The method tokens proven so far in this flow (readable as `/method_tokens`, a set source).
    pub method_tokens: BTreeSet<String>,
    /// The blind `usr_` subject handle (readable as `/subject`), never end-user data.
    pub subject_handle: String,
    /// The step outcome signals the engine emits (readable as boolean flow signals, for example
    /// `/mfa_required`).
    pub signals: SignalSet,
}

/// The closed set of step outcome signals a flow step emits (issue #92): boolean routing signals
/// the engine computes (any time-based need is pre-evaluated into one of these before the context
/// is assembled). The wire form is the `snake_case` name a `signals` field pointer names, for
/// example the pointer `/mfa_required` reads [`OutcomeSignal::MfaRequired`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum OutcomeSignal {
    /// The first factor was proven.
    PrimaryVerified,
    /// A second factor is required before completion.
    MfaRequired,
    /// A second factor must be enrolled before completion.
    EnrollRequired,
    /// Progressive profiling is pending before completion.
    ProfilingPending,
}

impl OutcomeSignal {
    /// The four outcome signal wire names, in declaration order. This is the closed set the
    /// load-time type check accepts under the `signals` source.
    pub const ALL: [&'static str; 4] = [
        "primary_verified",
        "mfa_required",
        "enroll_required",
        "profiling_pending",
    ];

    /// The `snake_case` wire name of this signal.
    #[must_use]
    pub fn as_wire(self) -> &'static str {
        match self {
            OutcomeSignal::PrimaryVerified => "primary_verified",
            OutcomeSignal::MfaRequired => "mfa_required",
            OutcomeSignal::EnrollRequired => "enroll_required",
            OutcomeSignal::ProfilingPending => "profiling_pending",
        }
    }

    /// Parse a wire name into a signal, or [`None`] for a name outside the closed set.
    #[must_use]
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw {
            "primary_verified" => Some(OutcomeSignal::PrimaryVerified),
            "mfa_required" => Some(OutcomeSignal::MfaRequired),
            "enroll_required" => Some(OutcomeSignal::EnrollRequired),
            "profiling_pending" => Some(OutcomeSignal::ProfilingPending),
            _ => None,
        }
    }
}

/// The step outcome signals asserted in a flow (issue #92): the set of signals that hold. A
/// signal not in the set reads as `false`, so the type is total and the engine only records the
/// signals it computed to be true. PR 4 populates it; PR 2 uses it in tests.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignalSet {
    asserted: BTreeSet<OutcomeSignal>,
}

impl SignalSet {
    /// An empty signal set: every signal reads as `false`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a signal to `value`, returning the updated set (a builder for tests). Setting a signal
    /// `false` removes it, so the set holds exactly the signals that are true.
    #[must_use]
    pub fn with(mut self, signal: OutcomeSignal, value: bool) -> Self {
        if value {
            self.asserted.insert(signal);
        } else {
            self.asserted.remove(&signal);
        }
        self
    }

    /// Whether a signal is asserted (holds). An absent signal is `false`.
    #[must_use]
    pub fn asserted(&self, signal: OutcomeSignal) -> bool {
        self.asserted.contains(&signal)
    }
}

/// The risk decision view a predicate reads (issue #92): the SHAPE mirroring what the flow's risk
/// decision exposes. PR 4 wires the real value; PR 2 defines the fields (`/level` reads
/// [`RiskView::level`], `/score` reads [`RiskView::score`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RiskView {
    /// The categorical risk level (compared as its wire string; no ordering, it is an enum).
    pub level: RiskLevel,
    /// The numeric risk score (compared as a number).
    pub score: u32,
}

/// A categorical risk level (issue #92): a closed, UNORDERED enum, so the load-time type check
/// rejects an ordering comparison (`lt`/`le`/`gt`/`ge`) against it. The wire form is the
/// `snake_case` name a `/level` comparison's string literal matches.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RiskLevel {
    /// Low risk.
    #[default]
    Low,
    /// Medium risk.
    Medium,
    /// High risk.
    High,
}

impl RiskLevel {
    /// The `snake_case` wire name of this level (the string a `/level` comparison matches).
    #[must_use]
    pub fn as_wire(self) -> &'static str {
        match self {
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
        }
    }
}

/// The result of resolving a [`FieldRef`] to a value for comparison (issue #92). A scalar is
/// comparable; a set, array, or object is [`Resolution::NonScalar`] and every comparison against
/// it is `false` (a total rule, never a panic).
#[derive(Clone, Debug, PartialEq)]
enum Resolution {
    /// A resolved scalar value (which may be [`ResolvedScalar::Null`] for an absent optional
    /// trait).
    Scalar(ResolvedScalar),
    /// A non-scalar source (a group or scope set, a trait array, or a trait object): not
    /// comparable, so a comparison against it is `false`.
    NonScalar,
}

/// A resolved scalar value the evaluator compares against a [`Literal`] (issue #92).
#[derive(Clone, Debug, PartialEq)]
enum ResolvedScalar {
    /// JSON null (a present null trait, or an absent optional trait).
    Null,
    /// A boolean (a flow signal, or a boolean trait).
    Bool(bool),
    /// A number (the risk score, or a numeric trait).
    Number(Number),
    /// A string (the step id, the subject handle, the risk level, or a string trait).
    Str(String),
}

/// Map a resolved JSON trait value to a [`Resolution`]: a scalar for a primitive, non-scalar for
/// an array or object.
fn value_to_resolution(value: &Value) -> Resolution {
    match value {
        Value::Null => Resolution::Scalar(ResolvedScalar::Null),
        Value::Bool(b) => Resolution::Scalar(ResolvedScalar::Bool(*b)),
        Value::Number(n) => Resolution::Scalar(ResolvedScalar::Number(n.clone())),
        Value::String(s) => Resolution::Scalar(ResolvedScalar::Str(s.clone())),
        Value::Array(_) | Value::Object(_) => Resolution::NonScalar,
    }
}

/// The signal a `signals`-source pointer names, or [`None`] for a pointer outside the closed
/// signal set (an empty, nested, or unknown name).
fn signal_from_pointer(pointer: &str) -> Option<OutcomeSignal> {
    pointer.strip_prefix('/').and_then(OutcomeSignal::from_wire)
}

/// Why evaluating a predicate failed at RUN time (issue #92). Evaluation is otherwise TOTAL: the
/// load-time type check guarantees a type-safe predicate, so the only runtime failure is a
/// predicate nested beyond [`MAX_PREDICATE_DEPTH`]. Kept an enum so a later milestone can add a
/// runtime failure mode without a breaking shape change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PredicateError {
    /// The predicate nests deeper than [`MAX_PREDICATE_DEPTH`]. A well-formed artifact never hits
    /// this (the load-time type check rejects an over-deep predicate first); it is the
    /// evaluator's own defense against stack exhaustion.
    TooDeep {
        /// The maximum depth the evaluator admits ([`MAX_PREDICATE_DEPTH`]).
        limit: usize,
    },
}

impl fmt::Display for PredicateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PredicateError::TooDeep { limit } => {
                write!(
                    f,
                    "predicate nests deeper than the maximum depth of {limit}"
                )
            }
        }
    }
}

impl std::error::Error for PredicateError {}

/// Evaluate a predicate against the typed context (issue #92): a PURE, DETERMINISTIC, TOTAL
/// function. The same predicate and context always return the same result, and no input the
/// load-time type check admits panics.
///
/// Resolution and comparison follow closed, documented total rules:
///
/// - A [`FieldRef`] resolves against its source; a source that is a set, array, or object is not
///   a scalar and every comparison against it is `false`.
/// - An absent optional trait resolves to JSON null; `null` equals only `null` under `eq`, so a
///   comparison of an absent trait against a non-null literal is `false` (and `ne` is its
///   negation).
/// - A comparison between incompatible scalar types (for example a string trait against a number
///   literal) is `false` under every operator, never a panic. Such a comparison only reaches the
///   evaluator through a dynamically-typed trait; the load-time type check rejects a statically
///   incompatible comparison.
/// - Ordering operators (`lt`/`le`/`gt`/`ge`) are defined only between two numbers or two
///   strings; every other ordering comparison is `false`.
/// - A [`Predicate::Member`] tests the named group or scope against the subject's group or scope
///   set.
/// - `and`/`or`/`not` short-circuit; `always` and `never` are the boolean constants.
///
/// # Errors
///
/// [`PredicateError::TooDeep`] if the predicate nests beyond [`MAX_PREDICATE_DEPTH`]. A predicate
/// that passed the load-time type check never nests this deep.
pub fn evaluate(predicate: &Predicate, ctx: &EvalContext) -> Result<bool, PredicateError> {
    evaluate_at_depth(predicate, ctx, 0)
}

/// Evaluate a predicate at a given nesting depth, refusing recursion past
/// [`MAX_PREDICATE_DEPTH`].
fn evaluate_at_depth(
    predicate: &Predicate,
    ctx: &EvalContext,
    depth: usize,
) -> Result<bool, PredicateError> {
    if depth > MAX_PREDICATE_DEPTH {
        return Err(PredicateError::TooDeep {
            limit: MAX_PREDICATE_DEPTH,
        });
    }
    match predicate {
        Predicate::Cmp { field, op, value } => Ok(eval_cmp(ctx, field, *op, value)),
        Predicate::In { field, values } => Ok(eval_in(ctx, field, values)),
        Predicate::Member { set, .. } => Ok(eval_member(ctx, set)),
        Predicate::And { operands } => {
            for operand in operands {
                if !evaluate_at_depth(operand, ctx, depth + 1)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        Predicate::Or { operands } => {
            for operand in operands {
                if evaluate_at_depth(operand, ctx, depth + 1)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Predicate::Not { operand } => Ok(!evaluate_at_depth(operand, ctx, depth + 1)?),
        Predicate::Always => Ok(true),
        Predicate::Never => Ok(false),
    }
}

/// Evaluate a comparison: resolve the field, then apply the operator under the total comparison
/// rules.
fn eval_cmp(ctx: &EvalContext, field: &FieldRef, op: CmpOp, value: &Literal) -> bool {
    compare(&ctx.resolve_scalar(field), op, value)
}

/// Evaluate an `in` test: `true` when the field's scalar value equals any literal in the list. A
/// non-scalar field is never a member.
fn eval_in(ctx: &EvalContext, field: &FieldRef, values: &[Literal]) -> bool {
    match ctx.resolve_scalar(field) {
        Resolution::Scalar(scalar) => values.iter().any(|literal| typed_eq(&scalar, literal)),
        Resolution::NonScalar => false,
    }
}

/// Evaluate a membership test: whether the named group or scope is in the subject's group or scope
/// set. The set kind selects which subject set to test (the load-time type check guarantees the
/// field source agrees with the set kind).
fn eval_member(ctx: &EvalContext, set: &MemberSet) -> bool {
    match set {
        MemberSet::Group { name } => ctx.subject_groups.contains(name),
        MemberSet::Scope { name } => ctx.subject_scopes.contains(name),
    }
}

/// Apply a comparison operator to a resolved field and a literal under the total rules. A
/// non-scalar field is `false` under every operator.
fn compare(resolution: &Resolution, op: CmpOp, literal: &Literal) -> bool {
    let scalar = match resolution {
        Resolution::Scalar(scalar) => scalar,
        Resolution::NonScalar => return false,
    };
    match op {
        CmpOp::Eq => typed_eq(scalar, literal),
        CmpOp::Ne => !typed_eq(scalar, literal),
        CmpOp::Lt | CmpOp::Le | CmpOp::Gt | CmpOp::Ge => match typed_ordering(scalar, literal) {
            Some(ordering) => apply_ordering(ordering, op),
            None => false,
        },
    }
}

/// Typed equality between a resolved scalar and a literal: equal only when the two share a type
/// and value. `null` equals only `null`; any cross-type comparison is `false`.
fn typed_eq(scalar: &ResolvedScalar, literal: &Literal) -> bool {
    match (scalar, literal) {
        (ResolvedScalar::Null, Literal::Null) => true,
        (ResolvedScalar::Bool(a), Literal::Bool(b)) => a == b,
        (ResolvedScalar::Number(a), Literal::Number(b)) => {
            num_ordering(a, b) == Some(Ordering::Equal)
        }
        (ResolvedScalar::Str(a), Literal::String(b)) => a == b,
        _ => false,
    }
}

/// The ordering between a resolved scalar and a literal, defined only between two numbers or two
/// strings; every other pairing (including any pairing with `null` or a boolean) is [`None`], so
/// an ordering comparison against it is `false`.
fn typed_ordering(scalar: &ResolvedScalar, literal: &Literal) -> Option<Ordering> {
    match (scalar, literal) {
        (ResolvedScalar::Number(a), Literal::Number(b)) => num_ordering(a, b),
        (ResolvedScalar::Str(a), Literal::String(b)) => Some(a.as_str().cmp(b.as_str())),
        _ => None,
    }
}

/// Order two JSON numbers by their `f64` value. JSON numbers are always finite, so the comparison
/// is total (never [`None`] for a real number); using `partial_cmp` keeps the float comparison off
/// the equality operator.
fn num_ordering(a: &Number, b: &Number) -> Option<Ordering> {
    match (a.as_f64(), b.as_f64()) {
        (Some(x), Some(y)) => x.partial_cmp(&y),
        _ => None,
    }
}

/// Whether an ordering satisfies an ordering operator.
fn apply_ordering(ordering: Ordering, op: CmpOp) -> bool {
    match op {
        CmpOp::Lt => ordering == Ordering::Less,
        CmpOp::Le => ordering != Ordering::Greater,
        CmpOp::Gt => ordering == Ordering::Greater,
        CmpOp::Ge => ordering != Ordering::Less,
        // Equality operators never reach this helper.
        CmpOp::Eq | CmpOp::Ne => false,
    }
}

/// The evaluator behind a decision (issue #92): the M11 SANDBOX SEAM. Today the only implementor
/// is the built-in [`Predicate`] (a decision expressed in the closed predicate grammar). A later
/// milestone (M11) adds a SANDBOXED evaluator as a SECOND implementor, selected by a new
/// [`DecisionSpec`] variant and gated by the capability manifest; the sandbox EXTENDS this seam,
/// it never gates or replaces the built-in predicate. Keeping [`DecisionSpec`] an enum and routing
/// a decision through this trait is the whole extension point; PR 2 builds no sandbox.
pub trait DecisionEvaluator {
    /// Evaluate this decision against the typed context.
    ///
    /// # Errors
    ///
    /// A [`PredicateError`] when evaluation cannot complete (for the built-in predicate, only
    /// [`PredicateError::TooDeep`]).
    fn evaluate(&self, ctx: &EvalContext) -> Result<bool, PredicateError>;
}

impl DecisionEvaluator for Predicate {
    fn evaluate(&self, ctx: &EvalContext) -> Result<bool, PredicateError> {
        evaluate(self, ctx)
    }
}

impl DecisionSpec {
    /// The [`DecisionEvaluator`] this decision routes through (issue #92). Today every decision is
    /// a built-in predicate; the M11 sandbox adds another variant that returns its own evaluator
    /// here, so a decision step's caller is agnostic to which evaluator backs it.
    #[must_use]
    pub fn evaluator(&self) -> &dyn DecisionEvaluator {
        match self {
            DecisionSpec::Predicate { predicate } => predicate,
        }
    }
}

/// The static type a [`FieldSource`] pointer yields (issue #92): what the load-time type check
/// unifies a comparison against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StaticType {
    /// A boolean (a flow signal): equality only, boolean literal.
    Bool,
    /// A number (the risk score, a numeric trait): every operator, number literal.
    Number,
    /// An ordered string (the step id, the subject handle): every operator, string literal.
    Str,
    /// A categorical, UNORDERED string (the risk level): equality only, string literal.
    Enum,
    /// A string set (the groups, the scopes, the method tokens): not a scalar, tested only by
    /// membership.
    StringSet,
    /// A dynamically-typed value (a sealed trait): the field-versus-literal type match is deferred
    /// to the evaluator's total rule (a mismatch is `false`), so only the operator-versus-literal
    /// check is static here.
    Dynamic,
}

/// Resolve the static type a source pointer yields, or [`None`] when a CLOSED source pointer names
/// no known field (a load-time [`PredicateTypeError::UnknownField`]). The dynamic trait source
/// accepts any pointer.
fn source_type(source: FieldSource, pointer: &str) -> Option<StaticType> {
    match source {
        FieldSource::Flow => match pointer {
            "/step_id" | "/subject" => Some(StaticType::Str),
            "/method_tokens" => Some(StaticType::StringSet),
            _ => None,
        },
        FieldSource::Signals => signal_from_pointer(pointer).map(|_| StaticType::Bool),
        FieldSource::SubjectTraits => Some(StaticType::Dynamic),
        FieldSource::SubjectGroups | FieldSource::SubjectScopes => Some(StaticType::StringSet),
        FieldSource::Risk => match pointer {
            "/level" => Some(StaticType::Enum),
            "/score" => Some(StaticType::Number),
            _ => None,
        },
    }
}

/// The static type of a literal (issue #92).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LiteralType {
    /// A JSON null.
    Null,
    /// A boolean.
    Bool,
    /// A number.
    Number,
    /// A string.
    Str,
}

/// The static type of a literal value.
fn literal_type(literal: &Literal) -> LiteralType {
    match literal {
        Literal::Null => LiteralType::Null,
        Literal::Bool(_) => LiteralType::Bool,
        Literal::Number(_) => LiteralType::Number,
        Literal::String(_) => LiteralType::Str,
    }
}

/// Why a predicate is not type-safe (issue #92), refused at LOAD time so the evaluator only ever
/// runs type-safe predicates. Every variant is OPERATOR-SAFE and VALUE-FREE: it names an RFC 6901
/// JSON Pointer into the artifact document, never end-user data, mirroring
/// [`crate::JourneyError`]. A comparison whose field source or type cannot unify is a load-time
/// error here; a comparison the evaluator resolves by a documented total rule (an absent or
/// dynamically-typed trait) is NOT an error here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PredicateTypeError {
    /// A field reads a CLOSED source pointer that names no known field (an unknown flow field, an
    /// unknown signal, or an unknown risk field). The dynamic trait source never triggers this.
    UnknownField {
        /// The RFC 6901 pointer to the offending `field` within the artifact.
        pointer: String,
        /// The source the field reads.
        source: FieldSource,
    },
    /// A comparison or `in` test addresses a SET source (a group set, a scope set, or the method
    /// tokens), which is not a scalar and cannot be compared; a set is tested only by membership.
    NotComparable {
        /// The RFC 6901 pointer to the offending `field` within the artifact.
        pointer: String,
    },
    /// An ordering operator (`lt`/`le`/`gt`/`ge`) is applied where ordering is undefined: a
    /// boolean or categorical (risk level) field, or a boolean or null literal.
    OrderingUndefined {
        /// The RFC 6901 pointer to the offending `op` within the artifact.
        pointer: String,
    },
    /// A literal's type cannot unify with the field's static type (for example a string literal
    /// against a boolean signal, or a number literal against the risk level). A dynamically-typed
    /// trait never triggers this (its match is a documented total rule at evaluation).
    LiteralTypeMismatch {
        /// The RFC 6901 pointer to the offending literal within the artifact.
        pointer: String,
    },
    /// A membership test's field source does not agree with its set kind: a group set requires the
    /// `subject_groups` source and a scope set requires the `subject_scopes` source.
    MemberSetMismatch {
        /// The RFC 6901 pointer to the offending `field` within the artifact.
        pointer: String,
    },
    /// The predicate nests deeper than [`MAX_PREDICATE_DEPTH`], so the evaluator would refuse it.
    TooDeep {
        /// The RFC 6901 pointer to the over-deep sub-predicate within the artifact.
        pointer: String,
    },
}

impl fmt::Display for PredicateTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PredicateTypeError::UnknownField { pointer, source } => {
                write!(f, "field at {pointer} names no known {source:?} field")
            }
            PredicateTypeError::NotComparable { pointer } => {
                write!(f, "field at {pointer} is a set and cannot be compared")
            }
            PredicateTypeError::OrderingUndefined { pointer } => {
                write!(
                    f,
                    "ordering operator at {pointer} is undefined for this type"
                )
            }
            PredicateTypeError::LiteralTypeMismatch { pointer } => {
                write!(f, "literal at {pointer} does not match the field type")
            }
            PredicateTypeError::MemberSetMismatch { pointer } => {
                write!(
                    f,
                    "membership field at {pointer} does not match its set kind"
                )
            }
            PredicateTypeError::TooDeep { pointer } => {
                write!(f, "predicate at {pointer} nests too deep")
            }
        }
    }
}

impl std::error::Error for PredicateTypeError {}

/// Type-check a predicate at a document location (issue #92), appending EVERY type error it finds
/// (in document order) to `errors`. `base` is the RFC 6901 pointer to this predicate within the
/// artifact (for example `/transitions/2/guard`), so each error locates the exact offending node.
/// Pure and deterministic.
pub fn typecheck_predicate(
    predicate: &Predicate,
    base: &str,
    errors: &mut Vec<PredicateTypeError>,
) {
    typecheck_at_depth(predicate, base, 0, errors);
}

/// Type-check a predicate at a given nesting depth, rejecting recursion past
/// [`MAX_PREDICATE_DEPTH`] so the evaluator never sees an over-deep predicate.
fn typecheck_at_depth(
    predicate: &Predicate,
    base: &str,
    depth: usize,
    errors: &mut Vec<PredicateTypeError>,
) {
    if depth > MAX_PREDICATE_DEPTH {
        errors.push(PredicateTypeError::TooDeep {
            pointer: base.to_owned(),
        });
        return;
    }
    match predicate {
        Predicate::Cmp { field, op, value } => typecheck_cmp(field, *op, value, base, errors),
        Predicate::In { field, values } => typecheck_in(field, values, base, errors),
        Predicate::Member { field, set } => typecheck_member(field, set, base, errors),
        Predicate::And { operands } | Predicate::Or { operands } => {
            for (index, operand) in operands.iter().enumerate() {
                let child = format!("{base}/operands/{index}");
                typecheck_at_depth(operand, &child, depth + 1, errors);
            }
        }
        Predicate::Not { operand } => {
            let child = format!("{base}/operand");
            typecheck_at_depth(operand, &child, depth + 1, errors);
        }
        Predicate::Always | Predicate::Never => {}
    }
}

/// Type-check a comparison: the field must resolve to a comparable type, the operator must be
/// defined for that type and literal, and (for a statically-typed field) the literal must unify
/// with the field type. The first failure found is reported.
fn typecheck_cmp(
    field: &FieldRef,
    op: CmpOp,
    value: &Literal,
    base: &str,
    errors: &mut Vec<PredicateTypeError>,
) {
    let Some(field_type) = source_type(field.source, &field.pointer) else {
        errors.push(PredicateTypeError::UnknownField {
            pointer: format!("{base}/field"),
            source: field.source,
        });
        return;
    };
    if field_type == StaticType::StringSet {
        errors.push(PredicateTypeError::NotComparable {
            pointer: format!("{base}/field"),
        });
        return;
    }
    let literal = literal_type(value);
    if is_ordering(op) && !ordering_is_defined(field_type, literal) {
        errors.push(PredicateTypeError::OrderingUndefined {
            pointer: format!("{base}/op"),
        });
        return;
    }
    if !literal_unifies(field_type, literal) {
        errors.push(PredicateTypeError::LiteralTypeMismatch {
            pointer: format!("{base}/value"),
        });
    }
}

/// Type-check an `in` test: the field must be a comparable scalar and every literal must unify
/// with the field type. The first failure found is reported.
fn typecheck_in(
    field: &FieldRef,
    values: &[Literal],
    base: &str,
    errors: &mut Vec<PredicateTypeError>,
) {
    let Some(field_type) = source_type(field.source, &field.pointer) else {
        errors.push(PredicateTypeError::UnknownField {
            pointer: format!("{base}/field"),
            source: field.source,
        });
        return;
    };
    if field_type == StaticType::StringSet {
        errors.push(PredicateTypeError::NotComparable {
            pointer: format!("{base}/field"),
        });
        return;
    }
    for (index, value) in values.iter().enumerate() {
        if !literal_unifies(field_type, literal_type(value)) {
            errors.push(PredicateTypeError::LiteralTypeMismatch {
                pointer: format!("{base}/values/{index}"),
            });
        }
    }
}

/// Type-check a membership test: a group set requires the `subject_groups` source and a scope set
/// requires the `subject_scopes` source, so the field is always a string set of the matching kind.
fn typecheck_member(
    field: &FieldRef,
    set: &MemberSet,
    base: &str,
    errors: &mut Vec<PredicateTypeError>,
) {
    let agrees = match set {
        MemberSet::Group { .. } => field.source == FieldSource::SubjectGroups,
        MemberSet::Scope { .. } => field.source == FieldSource::SubjectScopes,
    };
    if !agrees {
        errors.push(PredicateTypeError::MemberSetMismatch {
            pointer: format!("{base}/field"),
        });
    }
}

/// Whether an operator is an ordering operator (`lt`/`le`/`gt`/`ge`).
fn is_ordering(op: CmpOp) -> bool {
    matches!(op, CmpOp::Lt | CmpOp::Le | CmpOp::Gt | CmpOp::Ge)
}

/// Whether ordering is defined between a field's static type and a literal type: only two ordered
/// types (a number field with a number literal, an ordered string field with a string literal) or
/// a dynamic trait against a number or string literal.
fn ordering_is_defined(field_type: StaticType, literal: LiteralType) -> bool {
    match field_type {
        StaticType::Number => literal == LiteralType::Number,
        StaticType::Str => literal == LiteralType::Str,
        StaticType::Dynamic => matches!(literal, LiteralType::Number | LiteralType::Str),
        // A boolean, an enum, or a set has no ordering.
        StaticType::Bool | StaticType::Enum | StaticType::StringSet => false,
    }
}

/// Whether a literal type unifies with a field's static type for an equality test. A null literal
/// unifies with any scalar field (a presence test). A dynamic trait accepts any literal (the
/// field-versus-literal match is a total rule at evaluation).
fn literal_unifies(field_type: StaticType, literal: LiteralType) -> bool {
    if literal == LiteralType::Null {
        // `null` unifies with any scalar field as a presence test; a set is already rejected as
        // not comparable before this check.
        return field_type != StaticType::StringSet;
    }
    match field_type {
        StaticType::Bool => literal == LiteralType::Bool,
        StaticType::Number => literal == LiteralType::Number,
        StaticType::Str | StaticType::Enum => literal == LiteralType::Str,
        StaticType::Dynamic => true,
        StaticType::StringSet => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn field(source: FieldSource, pointer: &str) -> FieldRef {
        FieldRef {
            source,
            pointer: pointer.to_owned(),
        }
    }

    fn cmp(source: FieldSource, pointer: &str, op: CmpOp, value: Literal) -> Predicate {
        Predicate::Cmp {
            field: field(source, pointer),
            op,
            value,
        }
    }

    /// A populated context for the evaluation tests: a signal set, a trait document, a group and a
    /// scope, and a medium risk with a score.
    fn sample_context() -> EvalContext {
        EvalContext {
            flow: FlowContext {
                step_id: "primary".to_owned(),
                method_tokens: BTreeSet::from(["password".to_owned()]),
                subject_handle: "usr_abc".to_owned(),
                signals: SignalSet::new()
                    .with(OutcomeSignal::PrimaryVerified, true)
                    .with(OutcomeSignal::MfaRequired, true),
            },
            subject_traits: json!({
                "email_verified": true,
                "display_name": "Ada",
                "login_count": 7,
                "middle_name": null,
            }),
            subject_groups: BTreeSet::from(["staff".to_owned()]),
            subject_scopes: BTreeSet::from(["read".to_owned()]),
            risk: RiskView {
                level: RiskLevel::Medium,
                score: 42,
            },
        }
    }

    #[test]
    fn a_boolean_signal_compares_under_equality() {
        let ctx = sample_context();
        // The asserted signal is true.
        assert_eq!(
            evaluate(
                &cmp(
                    FieldSource::Signals,
                    "/mfa_required",
                    CmpOp::Eq,
                    Literal::Bool(true)
                ),
                &ctx
            ),
            Ok(true)
        );
        // An unasserted signal reads false.
        assert_eq!(
            evaluate(
                &cmp(
                    FieldSource::Signals,
                    "/enroll_required",
                    CmpOp::Eq,
                    Literal::Bool(false)
                ),
                &ctx
            ),
            Ok(true)
        );
        // ne is the negation of eq.
        assert_eq!(
            evaluate(
                &cmp(
                    FieldSource::Signals,
                    "/mfa_required",
                    CmpOp::Ne,
                    Literal::Bool(true)
                ),
                &ctx
            ),
            Ok(false)
        );
    }

    #[test]
    fn a_number_compares_under_every_ordering_operator() {
        let ctx = sample_context();
        let score = |op, n: i64| {
            evaluate(
                &cmp(
                    FieldSource::Risk,
                    "/score",
                    op,
                    Literal::Number(Number::from(n)),
                ),
                &ctx,
            )
        };
        // The score is 42.
        assert_eq!(score(CmpOp::Eq, 42), Ok(true));
        assert_eq!(score(CmpOp::Ne, 42), Ok(false));
        assert_eq!(score(CmpOp::Lt, 43), Ok(true));
        assert_eq!(score(CmpOp::Lt, 42), Ok(false));
        assert_eq!(score(CmpOp::Le, 42), Ok(true));
        assert_eq!(score(CmpOp::Gt, 41), Ok(true));
        assert_eq!(score(CmpOp::Gt, 42), Ok(false));
        assert_eq!(score(CmpOp::Ge, 42), Ok(true));
    }

    #[test]
    fn a_string_compares_under_equality_and_ordering() {
        let ctx = sample_context();
        // The step id is "primary".
        assert_eq!(
            evaluate(
                &cmp(
                    FieldSource::Flow,
                    "/step_id",
                    CmpOp::Eq,
                    Literal::String("primary".to_owned())
                ),
                &ctx
            ),
            Ok(true)
        );
        // Lexicographic ordering: "primary" < "z".
        assert_eq!(
            evaluate(
                &cmp(
                    FieldSource::Flow,
                    "/step_id",
                    CmpOp::Lt,
                    Literal::String("z".to_owned())
                ),
                &ctx
            ),
            Ok(true)
        );
        // The risk level compares as its wire string.
        assert_eq!(
            evaluate(
                &cmp(
                    FieldSource::Risk,
                    "/level",
                    CmpOp::Eq,
                    Literal::String("medium".to_owned())
                ),
                &ctx
            ),
            Ok(true)
        );
    }

    #[test]
    fn an_in_test_matches_membership_in_the_literal_list() {
        let ctx = sample_context();
        let in_levels = |values: Vec<Literal>| {
            evaluate(
                &Predicate::In {
                    field: field(FieldSource::Risk, "/level"),
                    values,
                },
                &ctx,
            )
        };
        // "medium" is in the list.
        assert_eq!(
            in_levels(vec![
                Literal::String("low".to_owned()),
                Literal::String("medium".to_owned()),
            ]),
            Ok(true)
        );
        // "medium" is not in a low-only list.
        assert_eq!(
            in_levels(vec![Literal::String("low".to_owned())]),
            Ok(false)
        );
    }

    #[test]
    fn a_membership_test_hits_a_group_and_a_scope_and_misses_others() {
        let ctx = sample_context();
        let member = |source, set| {
            evaluate(
                &Predicate::Member {
                    field: field(source, ""),
                    set,
                },
                &ctx,
            )
        };
        assert_eq!(
            member(
                FieldSource::SubjectGroups,
                MemberSet::Group {
                    name: "staff".to_owned()
                }
            ),
            Ok(true)
        );
        assert_eq!(
            member(
                FieldSource::SubjectGroups,
                MemberSet::Group {
                    name: "admin".to_owned()
                }
            ),
            Ok(false)
        );
        assert_eq!(
            member(
                FieldSource::SubjectScopes,
                MemberSet::Scope {
                    name: "read".to_owned()
                }
            ),
            Ok(true)
        );
        assert_eq!(
            member(
                FieldSource::SubjectScopes,
                MemberSet::Scope {
                    name: "write".to_owned()
                }
            ),
            Ok(false)
        );
    }

    #[test]
    fn boolean_combinators_short_circuit() {
        let ctx = sample_context();
        assert_eq!(
            evaluate(
                &Predicate::And {
                    operands: vec![Predicate::Always, Predicate::Never]
                },
                &ctx
            ),
            Ok(false)
        );
        assert_eq!(
            evaluate(
                &Predicate::Or {
                    operands: vec![Predicate::Never, Predicate::Always]
                },
                &ctx
            ),
            Ok(true)
        );
        assert_eq!(
            evaluate(
                &Predicate::Not {
                    operand: Box::new(Predicate::Never)
                },
                &ctx
            ),
            Ok(true)
        );
        // An empty conjunction is vacuously true; an empty disjunction is vacuously false.
        assert_eq!(
            evaluate(&Predicate::And { operands: vec![] }, &ctx),
            Ok(true)
        );
        assert_eq!(
            evaluate(&Predicate::Or { operands: vec![] }, &ctx),
            Ok(false)
        );
    }

    #[test]
    fn the_boolean_constants_evaluate() {
        let ctx = EvalContext::default();
        assert_eq!(evaluate(&Predicate::Always, &ctx), Ok(true));
        assert_eq!(evaluate(&Predicate::Never, &ctx), Ok(false));
    }

    #[test]
    fn a_present_trait_pointer_resolves_and_compares() {
        let ctx = sample_context();
        assert_eq!(
            evaluate(
                &cmp(
                    FieldSource::SubjectTraits,
                    "/email_verified",
                    CmpOp::Eq,
                    Literal::Bool(true)
                ),
                &ctx
            ),
            Ok(true)
        );
        assert_eq!(
            evaluate(
                &cmp(
                    FieldSource::SubjectTraits,
                    "/display_name",
                    CmpOp::Eq,
                    Literal::String("Ada".to_owned())
                ),
                &ctx
            ),
            Ok(true)
        );
        assert_eq!(
            evaluate(
                &cmp(
                    FieldSource::SubjectTraits,
                    "/login_count",
                    CmpOp::Ge,
                    Literal::Number(Number::from(5))
                ),
                &ctx
            ),
            Ok(true)
        );
    }

    #[test]
    fn an_absent_trait_follows_the_documented_null_rule() {
        let ctx = sample_context();
        // An absent optional trait resolves to null: eq null is true, eq a value is false, ne a
        // value is true, and ordering is false. No panic on any of these.
        let absent = |op, value| {
            evaluate(
                &cmp(FieldSource::SubjectTraits, "/never_set", op, value),
                &ctx,
            )
        };
        assert_eq!(absent(CmpOp::Eq, Literal::Null), Ok(true));
        assert_eq!(
            absent(CmpOp::Eq, Literal::String("x".to_owned())),
            Ok(false)
        );
        assert_eq!(absent(CmpOp::Ne, Literal::String("x".to_owned())), Ok(true));
        assert_eq!(
            absent(CmpOp::Lt, Literal::Number(Number::from(1))),
            Ok(false)
        );
        // A present-but-null trait behaves the same as an absent one.
        assert_eq!(
            evaluate(
                &cmp(
                    FieldSource::SubjectTraits,
                    "/middle_name",
                    CmpOp::Eq,
                    Literal::Null
                ),
                &ctx
            ),
            Ok(true)
        );
    }

    #[test]
    fn a_dynamic_trait_type_mismatch_is_false_never_a_panic() {
        let ctx = sample_context();
        // The trait is a string; comparing it to a number literal is a total false, not a panic.
        assert_eq!(
            evaluate(
                &cmp(
                    FieldSource::SubjectTraits,
                    "/display_name",
                    CmpOp::Eq,
                    Literal::Number(Number::from(1))
                ),
                &ctx
            ),
            Ok(false)
        );
        // ne of the mismatch is true (the negation), still no panic.
        assert_eq!(
            evaluate(
                &cmp(
                    FieldSource::SubjectTraits,
                    "/display_name",
                    CmpOp::Ne,
                    Literal::Bool(true)
                ),
                &ctx
            ),
            Ok(true)
        );
    }

    #[test]
    fn a_non_scalar_source_never_compares() {
        let ctx = sample_context();
        // A group set is not a scalar; every comparison against it is false.
        assert_eq!(
            evaluate(
                &cmp(
                    FieldSource::SubjectGroups,
                    "",
                    CmpOp::Eq,
                    Literal::String("staff".to_owned())
                ),
                &ctx
            ),
            Ok(false)
        );
        // A trait object is not a scalar either.
        let mut object_ctx = ctx;
        object_ctx.subject_traits = json!({ "address": { "city": "here" } });
        assert_eq!(
            evaluate(
                &cmp(
                    FieldSource::SubjectTraits,
                    "/address",
                    CmpOp::Eq,
                    Literal::Null
                ),
                &object_ctx
            ),
            Ok(false)
        );
    }

    #[test]
    fn evaluation_is_deterministic_across_repeated_calls() {
        let ctx = sample_context();
        let predicate = Predicate::And {
            operands: vec![
                cmp(
                    FieldSource::Signals,
                    "/mfa_required",
                    CmpOp::Eq,
                    Literal::Bool(true),
                ),
                Predicate::Member {
                    field: field(FieldSource::SubjectGroups, ""),
                    set: MemberSet::Group {
                        name: "staff".to_owned(),
                    },
                },
                cmp(
                    FieldSource::Risk,
                    "/score",
                    CmpOp::Lt,
                    Literal::Number(Number::from(50)),
                ),
            ],
        };
        let first = evaluate(&predicate, &ctx);
        for _ in 0..16 {
            assert_eq!(evaluate(&predicate, &ctx), first);
        }
        assert_eq!(first, Ok(true));
    }

    #[test]
    fn a_pathologically_deep_predicate_is_refused_without_overflow() {
        // A nest just past the bound: evaluation refuses it rather than recursing far enough to
        // exhaust the stack. The nest is shallow enough to construct and drop safely.
        let mut predicate = Predicate::Always;
        for _ in 0..(MAX_PREDICATE_DEPTH + 8) {
            predicate = Predicate::Not {
                operand: Box::new(predicate),
            };
        }
        assert_eq!(
            evaluate(&predicate, &EvalContext::default()),
            Err(PredicateError::TooDeep {
                limit: MAX_PREDICATE_DEPTH
            })
        );
        // A nest within the bound evaluates cleanly.
        let mut shallow = Predicate::Always;
        for _ in 0..4 {
            shallow = Predicate::Not {
                operand: Box::new(shallow),
            };
        }
        assert_eq!(evaluate(&shallow, &EvalContext::default()), Ok(true));
    }

    #[test]
    fn the_decision_evaluator_built_in_delegates_to_evaluate() {
        let ctx = sample_context();
        let spec = DecisionSpec::Predicate {
            predicate: cmp(
                FieldSource::Signals,
                "/mfa_required",
                CmpOp::Eq,
                Literal::Bool(true),
            ),
        };
        // The trait impl and the free function agree.
        assert_eq!(spec.evaluator().evaluate(&ctx), Ok(true));
        let predicate = cmp(
            FieldSource::Signals,
            "/mfa_required",
            CmpOp::Eq,
            Literal::Bool(true),
        );
        assert_eq!(
            DecisionEvaluator::evaluate(&predicate, &ctx),
            evaluate(&predicate, &ctx)
        );
    }

    #[test]
    fn the_type_check_accepts_a_well_typed_predicate() {
        let predicate = Predicate::And {
            operands: vec![
                cmp(
                    FieldSource::Signals,
                    "/mfa_required",
                    CmpOp::Eq,
                    Literal::Bool(true),
                ),
                cmp(
                    FieldSource::Risk,
                    "/score",
                    CmpOp::Lt,
                    Literal::Number(Number::from(50)),
                ),
                Predicate::In {
                    field: field(FieldSource::Risk, "/level"),
                    values: vec![
                        Literal::String("low".to_owned()),
                        Literal::String("medium".to_owned()),
                    ],
                },
                Predicate::Member {
                    field: field(FieldSource::SubjectGroups, ""),
                    set: MemberSet::Group {
                        name: "staff".to_owned(),
                    },
                },
                cmp(
                    FieldSource::SubjectTraits,
                    "/anything",
                    CmpOp::Eq,
                    Literal::String("x".to_owned()),
                ),
            ],
        };
        let mut errors = Vec::new();
        typecheck_predicate(&predicate, "/root", &mut errors);
        assert_eq!(errors, Vec::new());
    }

    #[test]
    fn the_type_check_rejects_ordering_on_a_boolean_signal() {
        let predicate = cmp(
            FieldSource::Signals,
            "/mfa_required",
            CmpOp::Lt,
            Literal::Bool(true),
        );
        let mut errors = Vec::new();
        typecheck_predicate(&predicate, "/g", &mut errors);
        assert_eq!(
            errors,
            vec![PredicateTypeError::OrderingUndefined {
                pointer: "/g/op".to_owned()
            }]
        );
    }

    #[test]
    fn the_type_check_rejects_a_numeric_op_on_the_risk_level_enum() {
        let predicate = cmp(
            FieldSource::Risk,
            "/level",
            CmpOp::Gt,
            Literal::String("low".to_owned()),
        );
        let mut errors = Vec::new();
        typecheck_predicate(&predicate, "/g", &mut errors);
        assert_eq!(
            errors,
            vec![PredicateTypeError::OrderingUndefined {
                pointer: "/g/op".to_owned()
            }]
        );
    }

    #[test]
    fn the_type_check_rejects_a_literal_that_cannot_unify() {
        // A string literal against a boolean signal.
        let predicate = cmp(
            FieldSource::Signals,
            "/mfa_required",
            CmpOp::Eq,
            Literal::String("yes".to_owned()),
        );
        let mut errors = Vec::new();
        typecheck_predicate(&predicate, "/g", &mut errors);
        assert_eq!(
            errors,
            vec![PredicateTypeError::LiteralTypeMismatch {
                pointer: "/g/value".to_owned()
            }]
        );
    }

    #[test]
    fn the_type_check_rejects_an_unknown_closed_field() {
        let predicate = cmp(
            FieldSource::Signals,
            "/teleported",
            CmpOp::Eq,
            Literal::Bool(true),
        );
        let mut errors = Vec::new();
        typecheck_predicate(&predicate, "/g", &mut errors);
        assert_eq!(
            errors,
            vec![PredicateTypeError::UnknownField {
                pointer: "/g/field".to_owned(),
                source: FieldSource::Signals,
            }]
        );
    }

    #[test]
    fn the_type_check_rejects_a_comparison_over_a_set() {
        let predicate = cmp(
            FieldSource::SubjectGroups,
            "",
            CmpOp::Eq,
            Literal::String("staff".to_owned()),
        );
        let mut errors = Vec::new();
        typecheck_predicate(&predicate, "/g", &mut errors);
        assert_eq!(
            errors,
            vec![PredicateTypeError::NotComparable {
                pointer: "/g/field".to_owned()
            }]
        );
    }

    #[test]
    fn the_type_check_rejects_membership_over_a_mismatched_set() {
        // A membership whose field is a non-set numeric source is a mismatch (Member over a
        // non-string set).
        let predicate = Predicate::Member {
            field: field(FieldSource::Risk, "/score"),
            set: MemberSet::Group {
                name: "staff".to_owned(),
            },
        };
        let mut errors = Vec::new();
        typecheck_predicate(&predicate, "/g", &mut errors);
        assert_eq!(
            errors,
            vec![PredicateTypeError::MemberSetMismatch {
                pointer: "/g/field".to_owned()
            }]
        );
        // A group set paired with the scope source is also a mismatch.
        let crossed = Predicate::Member {
            field: field(FieldSource::SubjectScopes, ""),
            set: MemberSet::Group {
                name: "staff".to_owned(),
            },
        };
        let mut crossed_errors = Vec::new();
        typecheck_predicate(&crossed, "/g", &mut crossed_errors);
        assert_eq!(
            crossed_errors,
            vec![PredicateTypeError::MemberSetMismatch {
                pointer: "/g/field".to_owned()
            }]
        );
    }

    #[test]
    fn the_type_check_locates_a_nested_error_with_a_precise_pointer() {
        let predicate = Predicate::And {
            operands: vec![
                Predicate::Always,
                Predicate::Not {
                    operand: Box::new(cmp(
                        FieldSource::Signals,
                        "/mfa_required",
                        CmpOp::Lt,
                        Literal::Bool(true),
                    )),
                },
            ],
        };
        let mut errors = Vec::new();
        typecheck_predicate(&predicate, "/transitions/0/guard", &mut errors);
        assert_eq!(
            errors,
            vec![PredicateTypeError::OrderingUndefined {
                pointer: "/transitions/0/guard/operands/1/operand/op".to_owned()
            }]
        );
    }

    #[test]
    fn the_type_check_rejects_an_over_deep_predicate() {
        let mut predicate = Predicate::Always;
        for _ in 0..(MAX_PREDICATE_DEPTH + 4) {
            predicate = Predicate::Not {
                operand: Box::new(predicate),
            };
        }
        let mut errors = Vec::new();
        typecheck_predicate(&predicate, "/g", &mut errors);
        assert!(
            errors
                .iter()
                .any(|error| matches!(error, PredicateTypeError::TooDeep { .. })),
            "an over-deep predicate is a load-time type error"
        );
    }
}
