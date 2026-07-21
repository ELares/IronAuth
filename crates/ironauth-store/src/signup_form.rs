// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-environment, per-client signup form store value types and fail-fast write
//! validation (issue #87, PR 1).
//!
//! A signup form is a DECLARATIVE definition, expressed as data, of which identity traits a
//! signup collects (and which a later-login progressive-profiling step collects): one row per
//! (tenant, environment, client). It is the config half of "signup forms as data"; the flow
//! contract's schema-to-node generation is PR 2 and is deliberately not touched here.
//!
//! This module holds only PURE value logic (no SQL, no clock, no entropy): the typed config
//! model that serializes to and from the persisted `fields` jsonb, and the fail-fast validation
//! that rejects a form BEFORE it is stored when a field names a nonexistent or type-incompatible
//! trait, or a rule WIDENS the scope's active trait schema. The persistence surface (the scoped
//! repository) lives in the repository module and consumes these types. The validation lands on
//! the #53 trait-schema surface: it resolves each field's RFC 6901 trait pointer with
//! [`TraitSchema::subschema_at`] and checks each rule with [`crate::trait_schema::narrows`].

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fmt;

use crate::trait_schema::{NarrowingViolation, TraitSchema, narrows};

/// A signup form to create or overwrite (issue #87). The `fields` are passed in as an
/// already-validated serialized JSON array string (the admin signup-forms path validates the
/// field list against the scope's active trait schema before the write); the store never
/// interprets it.
#[derive(Debug, Clone, Copy)]
pub struct NewSignupForm<'a> {
    /// The authorize client id this form governs (the per-environment natural key).
    pub client_id: &'a str,
    /// The serialized field list (a JSON array of field objects), stored verbatim as `jsonb`.
    pub fields_json: &'a str,
}

/// A stored signup form, read back (issue #87). The `fields_json` is the serialized field list
/// exactly as validated on write.
#[derive(Debug, Clone)]
pub struct SignupFormRecord {
    /// The `sgf_` signup form id.
    pub id: String,
    /// The authorize client id this form governs (the per-environment natural key).
    pub client_id: String,
    /// The serialized field list (a JSON array of field objects).
    pub fields_json: String,
}

/// Which step of the journey a field is collected at (issue #87). A `signup` field is collected
/// during registration; a `later_login` field is collected on a subsequent login as a
/// progressive-profiling step (PR 3 wires the later-login trigger).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignupStep {
    /// Collected during registration (the signup form).
    Signup,
    /// Collected on a subsequent login as a progressive-profiling step.
    LaterLogin,
}

/// One field of a signup form (issue #87): a reference to an identity trait PATH (an RFC 6901
/// JSON Pointer, the same pointer a [`crate::trait_schema::ValidationFailure`] carries), whether
/// it is required, its render order, the step it is collected at, a NARROWING-ONLY rule set (a
/// subset of the trait schema's closed keyword vocabulary that may only tighten the trait's
/// constraint), and the numeric message id of its label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignupFormField {
    /// The RFC 6901 JSON Pointer naming the identity trait this field collects.
    pub trait_pointer: String,
    /// Whether the field must be supplied.
    pub required: bool,
    /// The render order within the form (a total, deterministic order).
    pub order: u16,
    /// The step of the journey the field is collected at.
    pub step: SignupStep,
    /// The narrowing-only rule set: a JSON object over the trait schema's closed keyword
    /// vocabulary (`type` / `enum` / `minLength` / `maxLength` / `minItems` / `maxItems` /
    /// `minimum` / `maximum`), each of which may only TIGHTEN the trait's constraint.
    #[serde(default)]
    pub rules: Value,
    /// The numeric message id of the field's label (localizable through the locale bundles).
    pub label_message_id: u32,
}

/// The typed config document a signup form persists (issue #87): the field list, serialized to
/// and from the `fields` jsonb. It carries no secret and no PII: trait pointers, bounded rules,
/// and numeric ids only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignupFormConfig {
    /// The form's fields.
    pub fields: Vec<SignupFormField>,
}

impl SignupFormConfig {
    /// Parse a config document from the persisted `fields` jsonb text.
    ///
    /// # Errors
    ///
    /// [`serde_json::Error`] if the text is not a JSON array of well-formed field objects.
    pub fn from_fields_json(fields_json: &str) -> Result<Self, serde_json::Error> {
        let fields: Vec<SignupFormField> = serde_json::from_str(fields_json)?;
        Ok(Self { fields })
    }

    /// Serialize the field list to the JSON array text the store persists verbatim.
    ///
    /// # Errors
    ///
    /// [`serde_json::Error`] on a serialization fault (not reachable for a well-formed model).
    pub fn to_fields_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self.fields)
    }
}

/// The primitive trait types a signup form field can RENDER as an input (issue #87): a text,
/// number, integer, or boolean control. A trait whose resolved sub-schema type is not one of
/// these (an object or an array) has no renderable input and is rejected at write time.
const RENDERABLE_TYPES: [&str; 4] = ["string", "number", "integer", "boolean"];

/// Why a submitted signup form is not valid against the scope's active trait schema (issue #87).
/// Every variant is OPERATOR-SAFE and VALUE-FREE: it names a trait pointer, a keyword, or an
/// order, never a trait value, so a rejection carries no PII.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignupFormError {
    /// A field's `trait_pointer` does not resolve to any trait in the active schema.
    NonexistentTrait {
        /// The offending RFC 6901 trait pointer.
        pointer: String,
    },
    /// A field's resolved trait sub-schema is not a renderable input type (it is an object or
    /// an array, not a string / number / integer / boolean).
    TypeIncompatible {
        /// The offending RFC 6901 trait pointer.
        pointer: String,
    },
    /// A field's rule WIDENS the trait sub-schema at the named keyword (a rule may only tighten).
    WideningRule {
        /// The field's RFC 6901 trait pointer.
        pointer: String,
        /// The widening keyword (for example `minLength`).
        keyword: String,
    },
    /// Two fields share the same `order`, so the render order is not total.
    DuplicateOrder {
        /// The duplicated order.
        order: u16,
    },
    /// Two fields name the same `trait_pointer`.
    DuplicateTrait {
        /// The duplicated RFC 6901 trait pointer.
        pointer: String,
    },
}

impl fmt::Display for SignupFormError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignupFormError::NonexistentTrait { pointer } => {
                write!(f, "field names a nonexistent trait path {pointer}")
            }
            SignupFormError::TypeIncompatible { pointer } => {
                write!(
                    f,
                    "field trait path {pointer} is type-incompatible (not a renderable input)"
                )
            }
            SignupFormError::WideningRule { pointer, keyword } => {
                write!(f, "widening rule at {pointer}/{keyword}")
            }
            SignupFormError::DuplicateOrder { order } => {
                write!(f, "two fields share order {order}")
            }
            SignupFormError::DuplicateTrait { pointer } => {
                write!(f, "two fields name the same trait path {pointer}")
            }
        }
    }
}

impl std::error::Error for SignupFormError {}

/// FAIL-FAST validate a signup form against the scope's ACTIVE trait schema BEFORE it is stored
/// (issue #87, PR 1). This is the write-time gate: the store keeps only a form that passes.
///
/// Rejects (each operator-safe, value-free):
///
/// - a `trait_pointer` that does not resolve via [`TraitSchema::subschema_at`]
///   ([`SignupFormError::NonexistentTrait`]);
/// - a resolved sub-schema whose type is not renderable (not string / number / integer /
///   boolean) ([`SignupFormError::TypeIncompatible`]);
/// - a `rules` object that widens the trait via [`narrows`] ([`SignupFormError::WideningRule`]);
/// - a duplicate `order` ([`SignupFormError::DuplicateOrder`]); and
/// - a duplicate `trait_pointer` ([`SignupFormError::DuplicateTrait`]).
///
/// Deterministic: fields are checked in list order.
///
/// # Errors
///
/// The first [`SignupFormError`] encountered.
pub fn validate_against_schema(
    config: &SignupFormConfig,
    schema: &TraitSchema,
) -> Result<(), SignupFormError> {
    let mut seen_orders: BTreeSet<u16> = BTreeSet::new();
    let mut seen_pointers: BTreeSet<&str> = BTreeSet::new();
    for field in &config.fields {
        if !seen_orders.insert(field.order) {
            return Err(SignupFormError::DuplicateOrder { order: field.order });
        }
        if !seen_pointers.insert(field.trait_pointer.as_str()) {
            return Err(SignupFormError::DuplicateTrait {
                pointer: field.trait_pointer.clone(),
            });
        }
        let subschema = schema.subschema_at(&field.trait_pointer).ok_or_else(|| {
            SignupFormError::NonexistentTrait {
                pointer: field.trait_pointer.clone(),
            }
        })?;
        if !subschema_type_is_renderable(subschema) {
            return Err(SignupFormError::TypeIncompatible {
                pointer: field.trait_pointer.clone(),
            });
        }
        if let Err(NarrowingViolation { keyword, .. }) = narrows(&field.rules, subschema) {
            return Err(SignupFormError::WideningRule {
                pointer: field.trait_pointer.clone(),
                keyword,
            });
        }
    }
    Ok(())
}

/// Whether a resolved trait sub-schema declares a RENDERABLE input type (issue #87): its `type`
/// must be present and EVERY named type must be renderable (a string / number / integer /
/// boolean). A sub-schema with no `type`, or one that also permits an object or array, has no
/// unambiguous renderable input and is rejected.
fn subschema_type_is_renderable(subschema: &Value) -> bool {
    let Some(type_value) = subschema.get("type") else {
        return false;
    };
    match type_value {
        Value::String(name) => RENDERABLE_TYPES.contains(&name.as_str()),
        Value::Array(names) => {
            !names.is_empty()
                && names
                    .iter()
                    .all(|name| name.as_str().is_some_and(|n| RENDERABLE_TYPES.contains(&n)))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn schema() -> TraitSchema {
        TraitSchema::compile(
            &json!({
                "type": "object",
                "properties": {
                    "email": {"type": "string", "minLength": 3, "maxLength": 254},
                    "age": {"type": "integer", "minimum": 0, "maximum": 130},
                    "newsletter": {"type": "boolean"},
                    "address": {
                        "type": "object",
                        "properties": {"zip": {"type": "string"}}
                    }
                }
            })
            .to_string(),
        )
        .expect("schema compiles")
    }

    fn field(pointer: &str, order: u16, rules: Value) -> SignupFormField {
        SignupFormField {
            trait_pointer: pointer.to_owned(),
            required: true,
            order,
            step: SignupStep::Signup,
            rules,
            label_message_id: 1070,
        }
    }

    #[test]
    fn a_config_round_trips_through_the_fields_json() {
        let config = SignupFormConfig {
            fields: vec![
                field("/email", 0, json!({"minLength": 5})),
                field("/age", 1, json!({})),
            ],
        };
        let json = config.to_fields_json().expect("serialize");
        let parsed = SignupFormConfig::from_fields_json(&json).expect("parse");
        assert_eq!(parsed, config);
        // The step serializes to its snake_case wire form.
        assert!(json.contains("\"signup\""));
    }

    #[test]
    fn a_narrowing_form_over_renderable_traits_validates() {
        let config = SignupFormConfig {
            fields: vec![
                // Tighter string bounds narrow.
                field("/email", 0, json!({"minLength": 5, "maxLength": 100})),
                // A tighter numeric range narrows; an introduced enum narrows.
                field("/age", 1, json!({"minimum": 18})),
                field("/newsletter", 2, json!({})),
            ],
        };
        assert_eq!(validate_against_schema(&config, &schema()), Ok(()));
    }

    #[test]
    fn a_nonexistent_trait_path_is_rejected() {
        let config = SignupFormConfig {
            fields: vec![field("/nope", 0, json!({}))],
        };
        assert_eq!(
            validate_against_schema(&config, &schema()),
            Err(SignupFormError::NonexistentTrait {
                pointer: "/nope".to_owned()
            })
        );
    }

    #[test]
    fn a_type_incompatible_trait_is_rejected() {
        // `/address` resolves to an object sub-schema, which has no renderable input.
        let config = SignupFormConfig {
            fields: vec![field("/address", 0, json!({}))],
        };
        assert_eq!(
            validate_against_schema(&config, &schema()),
            Err(SignupFormError::TypeIncompatible {
                pointer: "/address".to_owned()
            })
        );
    }

    #[test]
    fn a_widening_rule_is_rejected_naming_the_pointer_and_keyword() {
        // The trait floor is minLength 3; a rule relaxing it to 1 widens.
        let config = SignupFormConfig {
            fields: vec![field("/email", 0, json!({"minLength": 1}))],
        };
        assert_eq!(
            validate_against_schema(&config, &schema()),
            Err(SignupFormError::WideningRule {
                pointer: "/email".to_owned(),
                keyword: "minLength".to_owned()
            })
        );
    }

    #[test]
    fn duplicate_order_and_duplicate_trait_are_rejected() {
        let dup_order = SignupFormConfig {
            fields: vec![field("/email", 0, json!({})), field("/age", 0, json!({}))],
        };
        assert_eq!(
            validate_against_schema(&dup_order, &schema()),
            Err(SignupFormError::DuplicateOrder { order: 0 })
        );
        let dup_trait = SignupFormConfig {
            fields: vec![field("/email", 0, json!({})), field("/email", 1, json!({}))],
        };
        assert_eq!(
            validate_against_schema(&dup_trait, &schema()),
            Err(SignupFormError::DuplicateTrait {
                pointer: "/email".to_owned()
            })
        );
    }
}
