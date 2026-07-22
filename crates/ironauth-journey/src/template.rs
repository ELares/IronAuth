// SPDX-License-Identifier: MIT OR Apache-2.0

//! Journey templates (issue #92, PR 3): a small registry of built-in journey patterns and the
//! pure [`materialize`] that substitutes typed parameters into a template body and returns a
//! CONCRETE journey. Materialization happens at LOAD, BEFORE validation, so validation and the
//! compiled table always see fully-resolved topology; there is no runtime template resolution and
//! therefore no non-determinism.
//!
//! A template fills DECLARED parameter slots only: it is not a macro or expression language.
//! Each template declares its own typed parameter schema, and an unknown template id, a missing or
//! mis-typed parameter, or a parameter that produces an invalid journey is a precise load-time
//! [`JourneyError`]. The concrete journey a template returns then goes through the normal
//! [`crate::validate`], exactly like a hand-authored journey.
//!
//! ## Purity discipline
//!
//! [`materialize`] is PURE: it reads the invocation and returns a value or a load-time error, with
//! NO clock, NO entropy, and NO I/O.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::artifact::{
    JOURNEY_ENGINE_VERSION, JOURNEY_SCHEMA_VERSION, Journey, Predicate, Step, StepKind, Transition,
};
use crate::validate::JourneyError;

/// The one built-in template id (issue #92, PR 3): an identifier-and-password first factor followed
/// by a second factor gated on a caller-supplied condition predicate. See
/// [`materialize`] for its parameter schema.
pub const TEMPLATE_IDENTIFIER_FIRST_CONDITIONAL_MFA: &str = "identifier_first_conditional_mfa";

/// The built-in template ids this crate provides (issue #92, PR 3), in registry order.
#[must_use]
pub fn template_ids() -> Vec<&'static str> {
    vec![TEMPLATE_IDENTIFIER_FIRST_CONDITIONAL_MFA]
}

/// A template invocation (issue #92, PR 3): the template id to materialize and the parameters that
/// fill its declared slots. This is an AUTHORING document distinct from a concrete [`Journey`]: it
/// materializes into a journey before validation, so a concrete journey never carries template
/// trivia. An unknown property is a hard parse error (`deny_unknown_fields`).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TemplateInvocation {
    /// The built-in template id to materialize (see [`template_ids`]).
    pub template: String,
    /// The parameters that fill the template's declared slots (a JSON object; each template
    /// documents its own typed schema).
    pub params: Value,
    /// An optional human-readable comment about the invocation (data, round-trip-safe).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// Materialize a template invocation into a concrete journey (issue #92, PR 3): a pure structural
/// substitution of the declared parameters into the template body. The returned journey is NOT yet
/// validated; the caller runs [`crate::validate`] on it exactly as for a hand-authored journey, so
/// a parameter that produces an invalid topology (for example an ill-typed guard predicate) surfaces
/// as a precise load-time [`JourneyError`] from that validation.
///
/// The `identifier_first_conditional_mfa` template accepts these parameters:
///
/// - `journey_id` (string, required): the id of the materialized journey.
/// - `mfa_condition` (predicate, required): the guard that routes the first factor to the second
///   factor; its negation routes straight to completion.
/// - `mfa_comment` (string, optional): a comment placed on the step-up transition; when omitted a
///   built-in comment is used.
///
/// # Errors
///
/// [`JourneyError::UnknownTemplate`] for an unknown template id;
/// [`JourneyError::MissingTemplateParam`] for an omitted required parameter; and
/// [`JourneyError::TemplateParamType`] for a parameter of the wrong type.
pub fn materialize(invocation: &TemplateInvocation) -> Result<Journey, JourneyError> {
    match invocation.template.as_str() {
        TEMPLATE_IDENTIFIER_FIRST_CONDITIONAL_MFA => {
            materialize_conditional_mfa(&invocation.params)
        }
        other => Err(JourneyError::UnknownTemplate {
            pointer: "/template".to_owned(),
            template: other.to_owned(),
        }),
    }
}

/// Materialize the `identifier_first_conditional_mfa` template body from its parameters.
fn materialize_conditional_mfa(params: &Value) -> Result<Journey, JourneyError> {
    let object = params.as_object().ok_or(JourneyError::TemplateParamType {
        pointer: "/params".to_owned(),
        param: "params".to_owned(),
    })?;

    let journey_id = required_string(object, "journey_id")?;
    let condition = required_predicate(object, "mfa_condition")?;
    let mfa_comment = optional_string(object, "mfa_comment")?
        .unwrap_or_else(|| "Step up when the condition holds.".to_owned());

    let mfa_required = Transition {
        from: "primary".to_owned(),
        to: "mfa".to_owned(),
        guard: Some(condition.clone()),
        comment: Some(mfa_comment),
    };
    let mfa_skipped = Transition {
        from: "primary".to_owned(),
        to: "done".to_owned(),
        guard: Some(Predicate::Not {
            operand: Box::new(condition),
        }),
        comment: Some("Complete directly when the condition does not hold.".to_owned()),
    };
    let after_mfa = Transition {
        from: "mfa".to_owned(),
        to: "done".to_owned(),
        guard: None,
        comment: None,
    };

    Ok(Journey {
        schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
        id: journey_id,
        engine_version: JOURNEY_ENGINE_VERSION,
        entry: "primary".to_owned(),
        comment: Some(
            "Identifier first, then a second factor only when the condition holds.".to_owned(),
        ),
        steps: vec![
            Step {
                comment: Some("The identifier and password first factor.".to_owned()),
                ..named_step("primary", StepKind::IdentifierPassword, Some("password"))
            },
            Step {
                comment: Some("The conditional second factor.".to_owned()),
                ..named_step("mfa", StepKind::MfaChallenge, Some("totp"))
            },
            Step {
                comment: Some("The session is minted here.".to_owned()),
                ..named_step("done", StepKind::Terminal, None)
            },
        ],
        transitions: vec![mfa_required, mfa_skipped, after_mfa],
        subflows: None,
        subflow_definitions: None,
    })
}

/// A step with no attachments (a template body helper).
fn named_step(id: &str, kind: StepKind, node_group: Option<&str>) -> Step {
    Step {
        id: id.to_owned(),
        kind,
        node_group: node_group.map(str::to_owned),
        subflow: None,
        decision: None,
        comment: None,
    }
}

/// Extract a required string parameter, or a precise load-time error.
fn required_string(
    object: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<String, JourneyError> {
    match object.get(name) {
        None => Err(JourneyError::MissingTemplateParam {
            pointer: "/params".to_owned(),
            param: name.to_owned(),
        }),
        Some(Value::String(value)) => Ok(value.clone()),
        Some(_) => Err(JourneyError::TemplateParamType {
            pointer: format!("/params/{name}"),
            param: name.to_owned(),
        }),
    }
}

/// Extract an optional string parameter, or a precise load-time error when present but not a string.
fn optional_string(
    object: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<Option<String>, JourneyError> {
    match object.get(name) {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(JourneyError::TemplateParamType {
            pointer: format!("/params/{name}"),
            param: name.to_owned(),
        }),
    }
}

/// Extract a required predicate parameter, decoding it from the parameter object, or a precise
/// load-time error.
fn required_predicate(
    object: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<Predicate, JourneyError> {
    let value = object.get(name).ok_or(JourneyError::MissingTemplateParam {
        pointer: "/params".to_owned(),
        param: name.to_owned(),
    })?;
    serde_json::from_value::<Predicate>(value.clone()).map_err(|_| {
        JourneyError::TemplateParamType {
            pointer: format!("/params/{name}"),
            param: name.to_owned(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{CmpOp, FieldRef, FieldSource, Literal};
    use crate::validate::validate;

    /// A boolean-signal equality predicate used as a well-typed MFA condition.
    fn mfa_required_condition() -> Predicate {
        Predicate::Cmp {
            field: FieldRef {
                source: FieldSource::Signals,
                pointer: "/mfa_required".to_owned(),
            },
            op: CmpOp::Eq,
            value: Literal::Bool(true),
        }
    }

    fn invocation(params: Value) -> TemplateInvocation {
        TemplateInvocation {
            template: TEMPLATE_IDENTIFIER_FIRST_CONDITIONAL_MFA.to_owned(),
            params,
            comment: None,
        }
    }

    #[test]
    fn a_template_materializes_to_a_valid_concrete_journey() {
        let params = serde_json::json!({
            "journey_id": "materialized_login",
            "mfa_condition": mfa_required_condition(),
        });
        let journey = materialize(&invocation(params)).expect("materialization succeeds");
        assert_eq!(journey.id, "materialized_login");
        // The materialized topology is fully resolved and validates clean.
        assert_eq!(validate(&journey), Ok(()));
    }

    #[test]
    fn template_and_param_comments_survive_materialization() {
        let params = serde_json::json!({
            "journey_id": "commented",
            "mfa_condition": mfa_required_condition(),
            "mfa_comment": "Escalate on the risk signal.",
        });
        let journey = materialize(&invocation(params)).expect("materialize");
        // The template body's own comments survive.
        assert_eq!(
            journey.comment.as_deref(),
            Some("Identifier first, then a second factor only when the condition holds.")
        );
        assert!(journey.steps.iter().any(
            |step| step.comment.as_deref() == Some("The identifier and password first factor.")
        ));
        // The parameter's comment appears on the step-up transition.
        assert!(
            journey
                .transitions
                .iter()
                .any(|t| t.comment.as_deref() == Some("Escalate on the risk signal."))
        );
    }

    #[test]
    fn an_unknown_template_id_is_a_precise_error() {
        let invocation = TemplateInvocation {
            template: "teleporter".to_owned(),
            params: serde_json::json!({}),
            comment: None,
        };
        assert_eq!(
            materialize(&invocation),
            Err(JourneyError::UnknownTemplate {
                pointer: "/template".to_owned(),
                template: "teleporter".to_owned(),
            })
        );
    }

    #[test]
    fn a_missing_required_param_is_a_precise_error() {
        // journey_id omitted.
        let params = serde_json::json!({ "mfa_condition": mfa_required_condition() });
        assert_eq!(
            materialize(&invocation(params)),
            Err(JourneyError::MissingTemplateParam {
                pointer: "/params".to_owned(),
                param: "journey_id".to_owned(),
            })
        );
    }

    #[test]
    fn a_mistyped_param_is_a_precise_error() {
        // journey_id supplied as a number.
        let params = serde_json::json!({
            "journey_id": 7,
            "mfa_condition": mfa_required_condition(),
        });
        assert_eq!(
            materialize(&invocation(params)),
            Err(JourneyError::TemplateParamType {
                pointer: "/params/journey_id".to_owned(),
                param: "journey_id".to_owned(),
            })
        );
    }

    #[test]
    fn a_param_that_produces_an_invalid_journey_fails_load_validation() {
        // A well-formed but ill-typed predicate (ordering on a boolean signal): materialization
        // succeeds structurally, and the caller's validate() rejects it with a precise pointer.
        let bad_condition = Predicate::Cmp {
            field: FieldRef {
                source: FieldSource::Signals,
                pointer: "/mfa_required".to_owned(),
            },
            op: CmpOp::Lt,
            value: Literal::Bool(true),
        };
        let params = serde_json::json!({
            "journey_id": "bad",
            "mfa_condition": bad_condition,
        });
        let journey = materialize(&invocation(params)).expect("materialize");
        let errors = validate(&journey).expect_err("an ill-typed guard is rejected");
        assert!(
            errors
                .iter()
                .any(|error| matches!(error, JourneyError::PredicateType(_))),
            "expected a PredicateType error, got {errors:?}"
        );
    }
}
