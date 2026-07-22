// SPDX-License-Identifier: MIT OR Apache-2.0

//! The declarative journey artifact (issue #92, PR 1): the code-first flow orchestration
//! FORMAT, its published JSON Schema, and the load-time validator.
//!
//! A journey artifact owns TOPOLOGY and ROUTING only: the steps a flow can occupy, the
//! transitions between them, and the guard predicates that route on typed signals. Each step
//! names a BUILT-IN [`StepKind`] executor (fixed Rust, defined by the engine); the artifact
//! never expresses step-internal security logic. The artifact compiles down to the engine's
//! transition table, so it drives the flow engine but never renders directly.
//!
//! ## Purity discipline
//!
//! This crate holds ONLY pure value logic: the serde artifact model, the derived JSON Schema,
//! and the deterministic load-time validator. It has NO database, NO clock, NO entropy, and NO
//! I/O, mirroring the identity-traits schema layer
//! (`ironauth_store::trait_schema`), so it runs on every build lane and its unit tests
//! exercise the validator directly. The flow engine, the persistence layer, and any
//! management surface consume these types; none of that lands here.
//!
//! PR 1 is the pure library only, with no engine change. It defines the predicate AST as DATA
//! and validates the artifact STRUCTURE. PR 2 adds the pure predicate EVALUATOR
//! ([`evaluate`]) over a typed [`EvalContext`], the load-time predicate type check that
//! guarantees the evaluator only runs type-safe predicates, and the [`DecisionEvaluator`] seam a
//! later milestone extends with a sandbox. PR 3 adds composable SUB-FLOWS ([`Subflow`],
//! [`compose`], [`builtin_subflows`]) and journey TEMPLATES ([`TemplateInvocation`],
//! [`materialize`]): a subflow is a reusable fragment a journey splices in with a
//! [`StepKind::SubflowCall`] step, resolved by id against a shared definition (so two journeys see
//! one definition), with reference cycles rejected at load; a template materializes into a concrete
//! journey before validation, so the compiled table always sees fully-resolved topology. Comments
//! survive both composition and materialization. The compile-to-table executor is PR 4.

mod artifact;
mod eval;
mod schema;
mod subflow;
mod template;
mod validate;

pub use artifact::{
    CmpOp, DecisionSpec, FieldRef, FieldSource, JOURNEY_ENGINE_VERSION, JOURNEY_SCHEMA_VERSION,
    Journey, Literal, MemberSet, Predicate, Step, StepId, StepKind, Subflow, SubflowId, SubflowRef,
    SubflowSource, Transition,
};
pub use eval::{
    DecisionEvaluator, EvalContext, FlowContext, MAX_PREDICATE_DEPTH, OutcomeSignal,
    PredicateError, PredicateTypeError, RiskLevel, RiskView, SignalSet, evaluate,
    typecheck_predicate,
};
pub use schema::journey_object_schema;
pub use subflow::{BUILTIN_MFA_STEP_UP, builtin_subflows, compose};
pub use template::{
    TEMPLATE_IDENTIFIER_FIRST_CONDITIONAL_MFA, TemplateInvocation, materialize, template_ids,
};
pub use validate::{JourneyError, NODE_GROUPS, validate};
