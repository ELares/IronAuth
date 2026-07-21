// SPDX-License-Identifier: MIT OR Apache-2.0

//! Schema to node generation and server authoritative validation for configured signup
//! fields (issue #87, PR 2).
//!
//! A signup form (issue #87, PR 1) is a declarative list of identity trait fields a signup
//! collects. This module is the flow contract half: the PURE functions that turn that config
//! plus the environment's active trait schema into the ordered [`Node`]s a registration flow
//! renders, and that validate a submitted value against the trait schema TRAIT
//! AUTHORITATIVELY.
//!
//! ## The critical contract: the trait always wins, the form only tightens
//!
//! PR 1's narrowing gate accepts an EMPTY or PARTIAL form rule against a constrained trait (a
//! form rule need not restate the trait's own constraints; it may only ADD tighter ones).
//! Therefore a submitted value MUST be validated against the TRAIT sub-schema authoritatively:
//! the trait's constraints ALWAYS apply, and the form's narrowed rules add tighter ones on
//! top. Validating against the form rule ALONE would let an empty or partial rule accept a
//! value the trait rejects. So [`validate_field_value`] validates the value against the trait
//! sub-schema AND (additionally) the form rule, and BOTH must pass. An empty form rule enforces
//! the FULL trait; a partial rule enforces the full trait plus its extra tightening. The
//! `an_empty_or_partial_rule_still_enforces_the_trait` test pins exactly this.
//!
//! The effective constraints carried to the wire ([`FieldConstraints`]) are the SAME thing the
//! server enforces (the trait keyword, tightened by the form keyword where the form carries
//! one), so a hosted page or a reference SPA validates from ONE source.

use std::collections::BTreeMap;

use serde_json::{Map, Number, Value};

use ironauth_store::{Scope, SignupFormConfig, SignupFormField, SignupStep, TraitSchema};

use super::message::{self, Message, MessageContext, MessageId};
use super::model::{FieldConstraints, InputType, Node, NodeAttributes, NodeGroup};
use crate::interaction;
use crate::state::OidcState;

/// Load the environment's active signup form for a flow (issue #87): resolve the authorize
/// client from the flow's `/authorize` resume target, read that client's active signup form,
/// and compile the scope's active trait schema. Returns the config, the compiled schema, and
/// the schema version, or [`None`] when the flow has no client, the client has no form, there
/// is no active schema, or any read faults (a form is a pure additive collection, never a hard
/// block, so any absence degrades to collecting nothing).
///
/// This is the ONE loader both the registration path (the Signup-step fields) and the
/// progressive profiling path (the LaterLogin-step fields) read the live form through, so a
/// management write reflects on the very next flow transition on either path.
pub(super) async fn load_active_signup_form(
    state: &OidcState,
    scope: Scope,
    return_to: Option<&str>,
) -> Option<(SignupFormConfig, TraitSchema, i32)> {
    let client_id = interaction::parse_resume(return_to)?.client_id.to_string();
    let record = state
        .store()
        .scoped(scope)
        .signup_forms()
        .get(&client_id)
        .await
        .ok()??;
    let config = SignupFormConfig::from_fields_json(&record.fields_json).ok()?;
    let active = state
        .store()
        .scoped(scope)
        .trait_schemas()
        .active()
        .await
        .ok()??;
    let schema = TraitSchema::compile(&active.schema_json).ok()?;
    Some((config, schema, active.version))
}

/// The message context key naming a field's RFC 6901 trait pointer (issue #87). Every generic
/// field message (the label and each validation error) carries the pointer here, so a locale
/// bundle keys per field copy on the pointer while the numeric id registry stays finite.
const FIELD_CONTEXT_KEY: &str = "field";

/// The IronAuth annotation keyword (mirrors `trait_schema`'s private constant), read off a
/// field's sub-schema to pick the email or phone input type for a verification address.
const ANNOTATION_KEYWORD: &str = "x-ironauth";

/// One field level validation failure (issue #87): the field's trait pointer (which maps back
/// to its node) and the generic numeric message id for the failure kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FieldFailure {
    /// The RFC 6901 trait pointer of the offending field (the stable node mapping key).
    pub trait_pointer: String,
    /// The generic numeric message id for the failure kind.
    pub message_id: MessageId,
}

/// The outcome of validating a signup submission (issue #87): the assembled partial trait
/// document on success, or the per field failures to attach to the field nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SignupValidation {
    /// Every collected field validated; the assembled partial trait document (top level and
    /// nested object fields, keyed by the trait pointers) is ready to persist.
    Valid(Value),
    /// One or more fields failed; each failure names its field pointer and message id.
    Invalid(Vec<FieldFailure>),
}

/// Build the ordered [`Node`]s for a step's configured signup fields (issue #87): each field
/// materializes as a typed [`NodeAttributes::Input`] in [`NodeGroup::Profile`], carrying its
/// effective (trait narrowed by the form) constraints as a client hint, with `sequence` from
/// the field's `order` so the node order is total and deterministic. A field whose pointer no
/// longer resolves in the active schema is skipped (a defensive no-op; the write time gate
/// already rejects a nonexistent pointer).
pub(super) fn signup_field_nodes(
    config: &SignupFormConfig,
    schema: &TraitSchema,
    step: SignupStep,
) -> Vec<Node> {
    signup_field_nodes_with_messages(config, schema, step, &[])
}

/// Build the step's signup field nodes with per field validation messages attached (issue
/// #87): identical to [`signup_field_nodes`], but each field whose pointer appears in
/// `failures` also carries the generic error message (the field pointer in its context) on
/// its node. The pointer to node mapping lives HERE (a failure names a trait pointer, a node
/// is built from the same field), so the same failure attaches to the SAME node on both the
/// browser and the API transport.
pub(super) fn signup_field_nodes_with_messages(
    config: &SignupFormConfig,
    schema: &TraitSchema,
    step: SignupStep,
    failures: &[FieldFailure],
) -> Vec<Node> {
    let mut fields: Vec<&SignupFormField> =
        config.fields.iter().filter(|f| f.step == step).collect();
    fields.sort_by_key(|field| field.order);
    fields
        .into_iter()
        .filter_map(|field| {
            schema.subschema_at(&field.trait_pointer).map(|subschema| {
                let mut node = field_node(field, subschema);
                if let Some(failure) = failures
                    .iter()
                    .find(|failure| failure.trait_pointer == field.trait_pointer)
                {
                    node.messages.push(Message::with_context(
                        failure.message_id,
                        MessageContext::one(FIELD_CONTEXT_KEY, &field.trait_pointer),
                    ));
                }
                node
            })
        })
        .collect()
}

/// Validate a signup submission for a step TRAIT AUTHORITATIVELY (issue #87): for each
/// configured field of the step, coerce its submitted value to the field's type, enforce
/// `required`, and validate the value against the trait sub-schema AND the form's narrowing
/// rule (both must pass, so the trait always wins). On success the assembled partial trait
/// document is returned; on failure every offending field's pointer and message id are
/// returned for node attachment. Deterministic: fields are processed in `order`, so the
/// failure list is stable across both transports.
pub(super) fn validate_signup_submission(
    config: &SignupFormConfig,
    schema: &TraitSchema,
    step: SignupStep,
    node_values: &BTreeMap<String, Value>,
) -> SignupValidation {
    let mut fields: Vec<&SignupFormField> =
        config.fields.iter().filter(|f| f.step == step).collect();
    fields.sort_by_key(|field| field.order);

    let mut failures = Vec::new();
    let mut document = Map::new();
    for field in fields {
        let Some(subschema) = schema.subschema_at(&field.trait_pointer) else {
            continue;
        };
        let effective = effective_constraints(subschema, &field.rules);
        let name = field_name(&field.trait_pointer);
        let coerced = coerce_value(node_values.get(&name), effective.value_type.as_deref());
        let Some(value) = coerced else {
            if field.required {
                failures.push(FieldFailure {
                    trait_pointer: field.trait_pointer.clone(),
                    message_id: message::SIGNUP_FIELD_REQUIRED,
                });
            }
            continue;
        };
        if let Some(message_id) = validate_field_value(subschema, &field.rules, &value) {
            failures.push(FieldFailure {
                trait_pointer: field.trait_pointer.clone(),
                message_id,
            });
        } else {
            insert_at_pointer(&mut document, &field.trait_pointer, value);
        }
    }

    if failures.is_empty() {
        SignupValidation::Valid(Value::Object(document))
    } else {
        SignupValidation::Invalid(failures)
    }
}

/// Build one field's [`Node`] (issue #87): a Profile group input, its type resolved from the
/// trait sub-schema (with the email/phone verification annotation), its name the pointer's
/// leaf token, its label the generic [`message::SIGNUP_FIELD_LABEL`] carrying the pointer, and
/// its effective constraints attached (omitted when the field is wholly unconstrained).
fn field_node(field: &SignupFormField, subschema: &Value) -> Node {
    let effective = effective_constraints(subschema, &field.rules);
    let input_type = input_type_for(subschema, effective.value_type.as_deref());
    let constraints = if effective.is_empty() {
        None
    } else {
        Some(effective)
    };
    let label = Message::with_context(
        message::SIGNUP_FIELD_LABEL,
        MessageContext::one(FIELD_CONTEXT_KEY, &field.trait_pointer),
    );
    Node::input(
        NodeGroup::Profile,
        field.order,
        NodeAttributes::Input {
            name: field_name(&field.trait_pointer),
            input_type,
            value: None,
            required: field.required,
            autocomplete: None,
            disabled: false,
            constraints,
        },
        Some(label),
    )
}

/// A field's stable node name (issue #87): the pointer's LAST reference token, RFC 6901
/// unescaped. A top level trait `/email` names the node `email`, exactly like the built in
/// identifier and password nodes.
fn field_name(pointer: &str) -> String {
    let last = pointer.rsplit('/').next().unwrap_or(pointer);
    unescape_token(last)
}

/// Reverse an RFC 6901 reference-token escape (`~1` to `/`, `~0` to `~`, in that order).
fn unescape_token(token: &str) -> String {
    token.replace("~1", "/").replace("~0", "~")
}

/// The effective constraints for a field (issue #87): each keyword's value taken from the
/// form rule where the form carries one (the form only ever TIGHTENS), else the trait
/// sub-schema. This is BOTH the client hint on the wire and the specific-error classifier's
/// source, so the hint always matches what the server enforces.
fn effective_constraints(subschema: &Value, rules: &Value) -> FieldConstraints {
    let rules = rules.as_object();
    let get = |keyword: &str| -> Option<&Value> {
        rules
            .and_then(|map| map.get(keyword))
            .or_else(|| subschema.get(keyword))
    };
    FieldConstraints {
        value_type: get("type").and_then(primary_type_name),
        allowed: get("enum").and_then(Value::as_array).cloned(),
        min_length: get("minLength").and_then(Value::as_u64),
        max_length: get("maxLength").and_then(Value::as_u64),
        min_items: get("minItems").and_then(Value::as_u64),
        max_items: get("maxItems").and_then(Value::as_u64),
        minimum: get("minimum").and_then(as_number).cloned(),
        maximum: get("maximum").and_then(as_number).cloned(),
    }
}

/// The [`Number`] a value holds, if it is a JSON number (`serde_json::Value` has no such
/// accessor; the range keywords keep the number verbatim so the wire hint is exact).
fn as_number(value: &Value) -> Option<&Number> {
    match value {
        Value::Number(number) => Some(number),
        _ => None,
    }
}

/// The primary primitive type name of a `type` keyword: a bare name, or the first name of a
/// type array (a renderable field has a single scalar type; the array form is tolerated).
fn primary_type_name(type_value: &Value) -> Option<String> {
    match type_value {
        Value::String(name) => Some(name.clone()),
        Value::Array(names) => names.iter().find_map(Value::as_str).map(str::to_owned),
        _ => None,
    }
}

/// The input type for a field (issue #87): a boolean renders as a checkbox; a string renders
/// as email or tel when the trait carries the matching verification annotation, else text;
/// every numeric type renders as text (the numeric bounds ride the constraints).
fn input_type_for(subschema: &Value, value_type: Option<&str>) -> InputType {
    let verification = subschema
        .get(ANNOTATION_KEYWORD)
        .and_then(|annotation| annotation.get("verification"))
        .and_then(Value::as_str);
    match value_type {
        Some("boolean") => InputType::Checkbox,
        Some("string") => match verification {
            Some("email") => InputType::Email,
            Some("phone" | "tel" | "sms") => InputType::Tel,
            _ => InputType::Text,
        },
        _ => InputType::Text,
    }
}

/// Coerce a submitted node value to the field's type (issue #87). A missing value, an
/// explicit null, or a blank string is [`None`] (an absent submission, which the caller maps
/// to `required`). A browser posts strings, so a string is parsed to the target type (a
/// checkbox to a boolean, a numeric string to a number); a value that does not parse is kept
/// as the raw string so the type check flags it. An API value (already typed JSON) passes
/// through.
fn coerce_value(raw: Option<&Value>, value_type: Option<&str>) -> Option<Value> {
    match raw? {
        Value::Null => None,
        Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                return None;
            }
            Some(coerce_string(text, trimmed, value_type))
        }
        other => Some(other.clone()),
    }
}

/// Coerce a non-blank submitted string to the field's type, falling back to the raw string
/// (so a value that cannot parse is flagged by the type check rather than silently dropped).
fn coerce_string(original: &str, trimmed: &str, value_type: Option<&str>) -> Value {
    match value_type {
        Some("boolean") => match trimmed.to_ascii_lowercase().as_str() {
            "true" | "on" | "1" | "yes" => Value::Bool(true),
            "false" | "off" | "0" | "no" => Value::Bool(false),
            _ => Value::String(original.to_owned()),
        },
        Some("integer") => trimmed.parse::<i64>().map_or_else(
            |_| Value::String(original.to_owned()),
            |number| Value::Number(number.into()),
        ),
        Some("number") => trimmed
            .parse::<f64>()
            .ok()
            .and_then(Number::from_f64)
            .map_or_else(|| Value::String(original.to_owned()), Value::Number),
        _ => Value::String(original.to_owned()),
    }
}

/// Validate one submitted value TRAIT AUTHORITATIVELY (issue #87, the critical contract):
/// the value must pass the trait sub-schema AND the form's narrowing rule. The trait ALWAYS
/// applies (so an empty or partial form rule still enforces the full trait); the form only
/// adds tightening. Returns the specific generic message id on failure, or [`None`] on pass.
fn validate_field_value(subschema: &Value, rules: &Value, value: &Value) -> Option<MessageId> {
    let trait_ok = node_accepts(subschema, value);
    // A null or absent rule tightens nothing; only an object rule adds constraints.
    let form_ok = match rules {
        Value::Object(_) => node_accepts(rules, value),
        _ => true,
    };
    if trait_ok && form_ok {
        return None;
    }
    Some(classify_failure(subschema, rules, value))
}

/// Whether a schema node (a trait sub-schema or a form rule) ACCEPTS a value, using the SAME
/// draft 2020-12 validator the write time gate and every trait write use (issue #87). A node
/// that does not compile is treated as rejecting (fail closed), though a sub-schema of a
/// compiled trait schema and a write validated form rule always compile.
fn node_accepts(node: &Value, value: &Value) -> bool {
    match TraitSchema::compile(&node.to_string()) {
        Ok(schema) => schema.validate(value).is_empty(),
        Err(_) => false,
    }
}

/// Pick the specific generic message id for a failing value (issue #87), from the EFFECTIVE
/// constraints in a deterministic priority: a type mismatch is an invalid format; a value
/// outside the enumerated set is not allowed; a value below a lower bound (length, items, or
/// numeric minimum) is too short; a value above an upper bound is too long. A failure the
/// closed vocabulary classifier does not name (which a scalar trait cannot produce) defaults
/// to an invalid format, so the value is never silently accepted.
fn classify_failure(subschema: &Value, rules: &Value, value: &Value) -> MessageId {
    let effective = effective_constraints(subschema, rules);
    if let Some(type_name) = &effective.value_type {
        if !type_name_matches(type_name, value) {
            return message::SIGNUP_FIELD_INVALID_FORMAT;
        }
    }
    if let Some(allowed) = &effective.allowed {
        if !allowed.iter().any(|candidate| candidate == value) {
            return message::SIGNUP_FIELD_NOT_ALLOWED;
        }
    }
    if below_lower_bound(&effective, value) {
        return message::SIGNUP_FIELD_TOO_SHORT;
    }
    if above_upper_bound(&effective, value) {
        return message::SIGNUP_FIELD_TOO_LONG;
    }
    message::SIGNUP_FIELD_INVALID_FORMAT
}

/// Whether a value falls below any effective lower bound (min length, min items, or minimum).
fn below_lower_bound(effective: &FieldConstraints, value: &Value) -> bool {
    if let (Some(min), Value::String(text)) = (effective.min_length, value) {
        if (text.chars().count() as u64) < min {
            return true;
        }
    }
    if let (Some(min), Value::Array(items)) = (effective.min_items, value) {
        if (items.len() as u64) < min {
            return true;
        }
    }
    match (&effective.minimum, value.as_f64()) {
        (Some(min), Some(actual)) => min.as_f64().is_some_and(|bound| actual < bound),
        _ => false,
    }
}

/// Whether a value rises above any effective upper bound (max length, max items, or maximum).
fn above_upper_bound(effective: &FieldConstraints, value: &Value) -> bool {
    if let (Some(max), Value::String(text)) = (effective.max_length, value) {
        if (text.chars().count() as u64) > max {
            return true;
        }
    }
    if let (Some(max), Value::Array(items)) = (effective.max_items, value) {
        if (items.len() as u64) > max {
            return true;
        }
    }
    match (&effective.maximum, value.as_f64()) {
        (Some(max), Some(actual)) => max.as_f64().is_some_and(|bound| actual > bound),
        _ => false,
    }
}

/// Whether a value matches a single JSON Schema primitive type name (`integer` accepts an
/// integral number, matching the draft 2020-12 rule the trait validator applies).
fn type_name_matches(name: &str, value: &Value) -> bool {
    match name {
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        "number" => value.is_number(),
        "integer" => {
            value.as_i64().is_some()
                || value.as_u64().is_some()
                || value
                    .as_f64()
                    .is_some_and(|number| number.fract() == 0.0 && number.is_finite())
        }
        "object" => value.is_object(),
        "array" => value.is_array(),
        "null" => value.is_null(),
        _ => true,
    }
}

/// Insert a validated value into the assembled partial trait document at its RFC 6901 pointer
/// (issue #87), building nested objects for a nested pointer. A renderable field resolves
/// through object properties, so object nesting is the shape assembled here.
fn insert_at_pointer(document: &mut Map<String, Value>, pointer: &str, value: Value) {
    let tokens: Vec<String> = pointer.split('/').skip(1).map(unescape_token).collect();
    insert_tokens(document, &tokens, value);
}

/// Insert `value` under `tokens` in `map`, descending through (creating) nested objects.
fn insert_tokens(map: &mut Map<String, Value>, tokens: &[String], value: Value) {
    match tokens {
        [] => {}
        [last] => {
            map.insert(last.clone(), value);
        }
        [head, rest @ ..] => {
            let entry = map
                .entry(head.clone())
                .or_insert_with(|| Value::Object(Map::new()));
            if let Value::Object(child) = entry {
                insert_tokens(child, rest, value);
            }
        }
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
                    "email": {
                        "type": "string",
                        "minLength": 3,
                        "maxLength": 254,
                        "x-ironauth": {"verification": "email"}
                    },
                    "phone": {"type": "string", "x-ironauth": {"verification": "phone"}},
                    "age": {"type": "integer", "minimum": 0, "maximum": 130},
                    "newsletter": {"type": "boolean"},
                    "tier": {"type": "string", "enum": ["free", "pro", "team"]},
                    "address": {
                        "type": "object",
                        "properties": {"zip": {"type": "string", "maxLength": 10}}
                    }
                }
            })
            .to_string(),
        )
        .expect("schema compiles")
    }

    fn field(pointer: &str, order: u16, required: bool, rules: Value) -> SignupFormField {
        SignupFormField {
            trait_pointer: pointer.to_owned(),
            required,
            order,
            step: SignupStep::Signup,
            rules,
            label_message_id: message::SIGNUP_FIELD_LABEL.0,
        }
    }

    fn config(fields: Vec<SignupFormField>) -> SignupFormConfig {
        SignupFormConfig { fields }
    }

    #[test]
    fn schema_to_node_derives_types_constraints_names_and_order() {
        let cfg = config(vec![
            field("/age", 1, true, json!({"minimum": 18})),
            field("/email", 0, true, json!({"maxLength": 100})),
            field("/newsletter", 2, false, json!({})),
            field("/tier", 3, false, json!({})),
        ]);
        let nodes = signup_field_nodes(&cfg, &schema(), SignupStep::Signup);
        // Deterministic order by field.order (email 0, age 1, newsletter 2, tier 3).
        let names: Vec<&str> = nodes
            .iter()
            .map(|node| match &node.attributes {
                NodeAttributes::Input { name, .. } => name.as_str(),
                NodeAttributes::Text { .. } => "text",
            })
            .collect();
        assert_eq!(names, vec!["email", "age", "newsletter", "tier"]);

        // Every node is a Profile group input, sequence = field.order, label carries the
        // field pointer in context.
        for node in &nodes {
            assert_eq!(node.group, NodeGroup::Profile);
            let label = node.label.as_ref().expect("field label");
            assert_eq!(label.id, message::SIGNUP_FIELD_LABEL);
            assert!(label.context.0.contains_key(FIELD_CONTEXT_KEY));
        }

        // The email field: an Email input (from the verification annotation), required, with
        // the effective constraints (trait minLength 3, form narrowed maxLength 100).
        let email = &nodes[0];
        match &email.attributes {
            NodeAttributes::Input {
                input_type,
                required,
                constraints,
                ..
            } => {
                assert_eq!(*input_type, InputType::Email);
                assert!(required);
                let constraints = constraints.as_ref().expect("email constraints");
                assert_eq!(constraints.value_type.as_deref(), Some("string"));
                assert_eq!(constraints.min_length, Some(3));
                assert_eq!(constraints.max_length, Some(100));
            }
            NodeAttributes::Text { .. } => panic!("email should be an input"),
        }

        // The age field: a Text input carrying the tightened minimum (18) and trait maximum.
        match &nodes[1].attributes {
            NodeAttributes::Input {
                input_type,
                constraints,
                ..
            } => {
                assert_eq!(*input_type, InputType::Text);
                let constraints = constraints.as_ref().expect("age constraints");
                assert_eq!(constraints.value_type.as_deref(), Some("integer"));
                assert_eq!(
                    constraints.minimum.as_ref().and_then(Number::as_i64),
                    Some(18)
                );
                assert_eq!(
                    constraints.maximum.as_ref().and_then(Number::as_i64),
                    Some(130)
                );
            }
            NodeAttributes::Text { .. } => panic!("age should be an input"),
        }

        // The newsletter boolean renders as a checkbox; the tier enum carries its allowed set.
        match &nodes[2].attributes {
            NodeAttributes::Input { input_type, .. } => {
                assert_eq!(*input_type, InputType::Checkbox);
            }
            NodeAttributes::Text { .. } => panic!("newsletter should be an input"),
        }
        match &nodes[3].attributes {
            NodeAttributes::Input { constraints, .. } => {
                let allowed = constraints
                    .as_ref()
                    .and_then(|c| c.allowed.as_ref())
                    .expect("tier enum");
                assert_eq!(allowed, &vec![json!("free"), json!("pro"), json!("team")]);
            }
            NodeAttributes::Text { .. } => panic!("tier should be an input"),
        }
    }

    #[test]
    fn a_later_login_field_is_not_a_signup_node() {
        let mut later = field("/age", 0, true, json!({}));
        later.step = SignupStep::LaterLogin;
        let cfg = config(vec![later, field("/email", 1, true, json!({}))]);
        let nodes = signup_field_nodes(&cfg, &schema(), SignupStep::Signup);
        assert_eq!(nodes.len(), 1);
    }

    #[test]
    fn a_valid_submission_assembles_the_partial_trait_document() {
        let cfg = config(vec![
            field("/email", 0, true, json!({})),
            field("/age", 1, true, json!({"minimum": 18})),
            field("/newsletter", 2, false, json!({})),
            field("/address/zip", 3, false, json!({})),
        ]);
        let mut values = BTreeMap::new();
        values.insert("email".to_owned(), json!("user@example.test"));
        values.insert("age".to_owned(), json!("21"));
        values.insert("newsletter".to_owned(), json!("on"));
        values.insert("zip".to_owned(), json!("94107"));
        let result = validate_signup_submission(&cfg, &schema(), SignupStep::Signup, &values);
        assert_eq!(
            result,
            SignupValidation::Valid(json!({
                "email": "user@example.test",
                "age": 21,
                "newsletter": true,
                "address": {"zip": "94107"}
            }))
        );
    }

    #[test]
    fn a_missing_required_field_is_flagged_required() {
        let cfg = config(vec![field("/email", 0, true, json!({}))]);
        let values = BTreeMap::new();
        let result = validate_signup_submission(&cfg, &schema(), SignupStep::Signup, &values);
        assert_eq!(
            result,
            SignupValidation::Invalid(vec![FieldFailure {
                trait_pointer: "/email".to_owned(),
                message_id: message::SIGNUP_FIELD_REQUIRED,
            }])
        );
    }

    #[test]
    fn each_failure_kind_maps_to_its_generic_id() {
        let cfg = config(vec![
            field("/email", 0, true, json!({})),
            field("/age", 1, true, json!({})),
            field("/tier", 2, true, json!({})),
            field("/newsletter", 3, true, json!({})),
        ]);
        let mut values = BTreeMap::new();
        values.insert("email".to_owned(), json!("ab")); // below trait minLength 3
        values.insert("age".to_owned(), json!("200")); // above trait maximum 130
        values.insert("tier".to_owned(), json!("enterprise")); // not in the trait enum
        values.insert("newsletter".to_owned(), json!("maybe")); // not a boolean
        let result = validate_signup_submission(&cfg, &schema(), SignupStep::Signup, &values);
        let SignupValidation::Invalid(failures) = result else {
            panic!("expected failures");
        };
        let map: BTreeMap<&str, MessageId> = failures
            .iter()
            .map(|f| (f.trait_pointer.as_str(), f.message_id))
            .collect();
        assert_eq!(map["/email"], message::SIGNUP_FIELD_TOO_SHORT);
        assert_eq!(map["/age"], message::SIGNUP_FIELD_TOO_LONG);
        assert_eq!(map["/tier"], message::SIGNUP_FIELD_NOT_ALLOWED);
        assert_eq!(map["/newsletter"], message::SIGNUP_FIELD_INVALID_FORMAT);
    }

    #[test]
    fn an_empty_or_partial_rule_still_enforces_the_trait() {
        // THE CRITICAL CONTRACT (PR 1 review finding 1): the form rule may be empty or
        // partial, yet a value the TRAIT rejects is STILL rejected, proving the server
        // validates trait authoritatively rather than against the form rule alone.

        // An EMPTY form rule: the trait's minLength 3 still rejects "ab".
        let empty = config(vec![field("/email", 0, true, json!({}))]);
        let mut values = BTreeMap::new();
        values.insert("email".to_owned(), json!("ab"));
        assert_eq!(
            validate_signup_submission(&empty, &schema(), SignupStep::Signup, &values),
            SignupValidation::Invalid(vec![FieldFailure {
                trait_pointer: "/email".to_owned(),
                message_id: message::SIGNUP_FIELD_TOO_SHORT,
            }]),
            "an empty rule must still enforce the trait's minLength"
        );

        // A PARTIAL form rule that narrows ONLY the maximum: the trait's minLength 3 still
        // rejects "ab" (the rule never restated minLength, and it still applies).
        let partial = config(vec![field("/email", 0, true, json!({"maxLength": 100}))]);
        assert_eq!(
            validate_signup_submission(&partial, &schema(), SignupStep::Signup, &values),
            SignupValidation::Invalid(vec![FieldFailure {
                trait_pointer: "/email".to_owned(),
                message_id: message::SIGNUP_FIELD_TOO_SHORT,
            }]),
            "a partial rule must still enforce the trait's unrestated minLength"
        );

        // The SAME partial rule accepts a value that satisfies BOTH the trait and the rule.
        values.insert("email".to_owned(), json!("valid@example.test"));
        assert!(matches!(
            validate_signup_submission(&partial, &schema(), SignupStep::Signup, &values),
            SignupValidation::Valid(_)
        ));
    }

    #[test]
    fn the_form_rule_tightens_on_top_of_the_trait() {
        // The form narrows minLength to 5; a 3 char value satisfies the trait (minLength 3)
        // but the tighter form rule rejects it as too short.
        let cfg = config(vec![field("/email", 0, true, json!({"minLength": 5}))]);
        let mut values = BTreeMap::new();
        values.insert("email".to_owned(), json!("a@b.test")); // 8 chars, ok
        assert!(matches!(
            validate_signup_submission(&cfg, &schema(), SignupStep::Signup, &values),
            SignupValidation::Valid(_)
        ));
        values.insert("email".to_owned(), json!("a@b")); // 3 chars, ok for trait, short for form
        assert_eq!(
            validate_signup_submission(&cfg, &schema(), SignupStep::Signup, &values),
            SignupValidation::Invalid(vec![FieldFailure {
                trait_pointer: "/email".to_owned(),
                message_id: message::SIGNUP_FIELD_TOO_SHORT,
            }])
        );
    }
}
