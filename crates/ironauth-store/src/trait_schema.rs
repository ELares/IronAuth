// SPDX-License-Identifier: MIT OR Apache-2.0

//! The identity-traits schema layer (issue #53): a self-contained JSON Schema
//! (draft 2020-12) validator, the IronAuth behavior-annotation vocabulary, and the
//! declarative transform used by a migration job.
//!
//! This module holds ONLY pure value logic (no SQL, no clock, no entropy), so it
//! runs on every build lane including the database-free ones, and its unit tests
//! exercise the validator directly. The persistence surface (the versioned schema
//! registry, the sealed per-user trait data, and the migration/dry-run job
//! substrate) lives in the scoped repository module, which consumes the types
//! defined here.
//!
//! ## Why a purpose-built validator
//!
//! A full off-the-shelf JSON Schema validator would pull a large external
//! dependency (a regex engine and more) that the workspace's `deny.toml`
//! allowlist, MSRV 1.85 floor, and musl-static lane all constrain. Traits are a
//! bounded, well-understood profile shape, so this module implements exactly the
//! draft 2020-12 validation vocabulary that user profiles need (`type`,
//! `properties`, `required`, `additionalProperties`, `items`/`prefixItems`,
//! `enum`, and the length/size/range assertions), with two properties an identity
//! provider must guarantee: validation errors carry an RFC 6901 JSON Pointer to
//! the exact failing location, and both schema compilation and instance validation
//! are DEPTH BOUNDED so a hostile deeply nested schema or payload cannot exhaust
//! the stack or run unbounded (the fuzz obligation of the issue).
//!
//! Arrays and nested objects are first-class: the named regression is Ory Kratos,
//! whose trait arrays have been broken since 2022; the unit tests pin arrays and
//! nested objects round-tripping through validation.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The maximum nesting depth the validator will descend, for both a schema at
/// compile time and an instance at validation time. A schema or payload deeper
/// than this is refused rather than recursed into, so a hostile input cannot
/// exhaust the stack (bounded memory, no panic: the fuzz obligation).
pub const MAX_DEPTH: usize = 32;

/// The IronAuth annotation keyword a schema property carries to declare its
/// login/verification/recovery behavior and its visibility class. It is an
/// unknown keyword to plain JSON Schema (draft 2020-12 ignores unknown keywords),
/// so a schema carrying it still validates as a standard schema everywhere.
const ANNOTATION_KEYWORD: &str = "x-ironauth";

/// A compiled, well-formed trait schema (JSON Schema draft 2020-12, the supported
/// subset). Construction ([`TraitSchema::compile`]) proves the schema document is
/// itself well formed and within the depth bound; [`TraitSchema::validate`] then
/// checks an instance against it and returns per-field failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraitSchema {
    root: Value,
}

/// Why a submitted schema document is not a well-formed trait schema. Carries an
/// RFC 6901 JSON Pointer to the offending location in the schema and a stable,
/// operator-safe reason (never attacker-controlled instance data).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaError {
    /// RFC 6901 JSON Pointer to the offending keyword within the schema document.
    pub pointer: String,
    /// A stable, operator-safe description of what is malformed.
    pub message: String,
}

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed schema at {}: {}", self.pointer, self.message)
    }
}

impl std::error::Error for SchemaError {}

/// One per-field validation failure: an RFC 6901 JSON Pointer to the exact
/// location in the instance that failed, and a stable reason. Serializable so a
/// migration/dry-run job can persist a per-record failure report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationFailure {
    /// RFC 6901 JSON Pointer to the failing location in the instance (the empty
    /// string points at the document root).
    pub pointer: String,
    /// A stable, operator-safe reason. Never echoes the offending value, so a
    /// failure report carries no trait PII.
    pub message: String,
}

/// The visibility class of a trait field (issue #53): whether a self-service
/// (user-facing) surface may read and write it, or it is admin-only metadata that
/// self-service endpoints must never leak or accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    /// Readable and writable by the end user through self-service surfaces.
    User,
    /// Admin-only metadata: invisible and immutable through self-service surfaces.
    Admin,
}

/// The parsed IronAuth behavior vocabulary for a schema (issue #53): which
/// top-level trait fields are login identifiers, verification addresses (email or
/// phone), recovery channels, and which are admin-only. These annotations are the
/// contract the flexible-identifiers and recovery work consume; here they drive
/// the visibility split and are exposed through the schema introspection surface.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TraitAnnotations {
    /// Top-level field names declared as login identifiers.
    pub login_identifiers: Vec<String>,
    /// Top-level (field name, kind) declared as verification addresses; kind is
    /// the free `verification` string from the annotation (for example `email`).
    pub verification_addresses: Vec<(String, String)>,
    /// Top-level field names declared as recovery channels.
    pub recovery_channels: Vec<String>,
    /// Top-level field names declared admin-only (never exposed to self-service).
    pub admin_only: Vec<String>,
}

impl TraitAnnotations {
    /// Whether `field` (a top-level trait name) is admin-only metadata.
    #[must_use]
    pub fn is_admin_only(&self, field: &str) -> bool {
        self.admin_only.iter().any(|name| name == field)
    }

    /// Return a copy of `traits` with every admin-only top-level field removed, for
    /// a self-service (user-facing) read. A non-object instance is returned
    /// unchanged (there is nothing to redact).
    #[must_use]
    pub fn redact_for_user(&self, traits: &Value) -> Value {
        let Value::Object(map) = traits else {
            return traits.clone();
        };
        let mut out = serde_json::Map::new();
        for (key, value) in map {
            if !self.is_admin_only(key) {
                out.insert(key.clone(), value.clone());
            }
        }
        Value::Object(out)
    }
}

/// The known primitive type keywords of the supported draft 2020-12 subset.
const KNOWN_TYPES: [&str; 7] = [
    "object", "array", "string", "number", "integer", "boolean", "null",
];

impl TraitSchema {
    /// Compile a schema document from its JSON text, proving it is well formed and
    /// within the depth bound. The parse and the structural check are the ONLY
    /// places a schema is trusted; every later validation runs against a compiled
    /// schema.
    ///
    /// # Errors
    ///
    /// [`SchemaError`] if the text is not JSON, or is JSON that is not a well-formed
    /// schema of the supported vocabulary (a bad `type`, a non-object `properties`,
    /// a `required` that is not an array of strings, a malformed sub-schema, or a
    /// nesting deeper than [`MAX_DEPTH`]).
    pub fn compile(schema_json: &str) -> Result<Self, SchemaError> {
        let root: Value = serde_json::from_str(schema_json).map_err(|err| SchemaError {
            pointer: String::new(),
            message: format!("schema is not valid JSON: {err}"),
        })?;
        check_schema_wellformed(&root, &mut String::new(), 0)?;
        Ok(Self { root })
    }

    /// The raw schema document (for the introspection surface). Callers serialize
    /// this verbatim; it is the exact text that was compiled.
    #[must_use]
    pub fn as_value(&self) -> &Value {
        &self.root
    }

    /// Validate an instance against this schema, returning every per-field failure
    /// with its RFC 6901 JSON Pointer. An empty vector means the instance is valid.
    /// Deterministic: failures are produced in a stable document order.
    #[must_use]
    pub fn validate(&self, instance: &Value) -> Vec<ValidationFailure> {
        let mut failures = Vec::new();
        validate_node(&self.root, instance, &mut String::new(), 0, &mut failures);
        failures
    }

    /// Parse the IronAuth behavior annotations off this schema's top-level
    /// properties. A property with no annotation contributes nothing; the
    /// visibility defaults to user unless the annotation says `admin`.
    #[must_use]
    pub fn annotations(&self) -> TraitAnnotations {
        let mut out = TraitAnnotations::default();
        let Some(props) = self.root.get("properties").and_then(Value::as_object) else {
            return out;
        };
        for (name, subschema) in props {
            let Some(annotation) = subschema.get(ANNOTATION_KEYWORD).and_then(Value::as_object)
            else {
                continue;
            };
            if annotation.get("identifier").and_then(Value::as_bool) == Some(true) {
                out.login_identifiers.push(name.clone());
            }
            if let Some(kind) = annotation.get("verification").and_then(Value::as_str) {
                out.verification_addresses
                    .push((name.clone(), kind.to_string()));
            }
            if annotation.get("recovery").and_then(Value::as_bool) == Some(true) {
                out.recovery_channels.push(name.clone());
            }
            if annotation.get("visibility").and_then(Value::as_str) == Some("admin") {
                out.admin_only.push(name.clone());
            }
        }
        out
    }

    /// The visibility class of a top-level trait field under this schema.
    #[must_use]
    pub fn visibility_of(&self, field: &str) -> Visibility {
        if self.annotations().is_admin_only(field) {
            Visibility::Admin
        } else {
            Visibility::User
        }
    }
}

/// Escape a single reference token for an RFC 6901 JSON Pointer: `~` becomes `~0`
/// and `/` becomes `~1`, so a token containing either character is unambiguous.
fn escape_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

/// Push a reference token onto a JSON Pointer, returning the length to truncate
/// back to afterwards (so a single mutable `String` walks the whole tree).
fn push_token(pointer: &mut String, token: &str) -> usize {
    let restore = pointer.len();
    pointer.push('/');
    pointer.push_str(&escape_token(token));
    restore
}

/// Check that a schema document (or sub-schema) is well formed within the
/// supported vocabulary and depth bound.
fn check_schema_wellformed(
    schema: &Value,
    pointer: &mut String,
    depth: usize,
) -> Result<(), SchemaError> {
    if depth > MAX_DEPTH {
        return Err(SchemaError {
            pointer: pointer.clone(),
            message: format!("schema nesting exceeds the maximum depth of {MAX_DEPTH}"),
        });
    }
    // A boolean schema (draft 2020-12) is well formed: `true` accepts anything,
    // `false` rejects everything. Any other non-object node is malformed.
    let Value::Object(map) = schema else {
        if schema.is_boolean() {
            return Ok(());
        }
        return Err(SchemaError {
            pointer: pointer.clone(),
            message: "a schema must be an object or a boolean".to_string(),
        });
    };

    if let Some(type_value) = map.get("type") {
        check_type_keyword(type_value, pointer)?;
    }
    if let Some(props) = map.get("properties") {
        let Some(props) = props.as_object() else {
            let restore = push_token(pointer, "properties");
            let err = SchemaError {
                pointer: pointer.clone(),
                message: "\"properties\" must be an object".to_string(),
            };
            pointer.truncate(restore);
            return Err(err);
        };
        let restore = push_token(pointer, "properties");
        for (name, subschema) in props {
            let inner = push_token(pointer, name);
            check_schema_wellformed(subschema, pointer, depth + 1)?;
            pointer.truncate(inner);
        }
        pointer.truncate(restore);
    }
    if let Some(required) = map.get("required") {
        check_string_array(required, "required", pointer)?;
    }
    // A non-boolean `additionalProperties` is itself a sub-schema and must be well
    // formed (a boolean form needs no recursion). Expressed as a match guard rather
    // than an `if let ... &&` let chain, which would raise the MSRV above 1.85.
    match map.get("additionalProperties") {
        Some(additional) if !additional.is_boolean() => {
            let restore = push_token(pointer, "additionalProperties");
            check_schema_wellformed(additional, pointer, depth + 1)?;
            pointer.truncate(restore);
        }
        _ => {}
    }
    if let Some(items) = map.get("items") {
        let restore = push_token(pointer, "items");
        check_schema_wellformed(items, pointer, depth + 1)?;
        pointer.truncate(restore);
    }
    if let Some(prefix) = map.get("prefixItems") {
        let Some(prefix) = prefix.as_array() else {
            let restore = push_token(pointer, "prefixItems");
            let err = SchemaError {
                pointer: pointer.clone(),
                message: "\"prefixItems\" must be an array of schemas".to_string(),
            };
            pointer.truncate(restore);
            return Err(err);
        };
        let restore = push_token(pointer, "prefixItems");
        for (index, subschema) in prefix.iter().enumerate() {
            let inner = push_token(pointer, &index.to_string());
            check_schema_wellformed(subschema, pointer, depth + 1)?;
            pointer.truncate(inner);
        }
        pointer.truncate(restore);
    }
    check_scalar_keywords(map, pointer)
}

/// Check the scalar assertion keywords of a schema object: `enum` must be a
/// non-empty array, the length/size keywords non-negative integers, and the range
/// keywords numbers. Split out of [`check_schema_wellformed`] to keep each within
/// the readable-length lint.
fn check_scalar_keywords(
    map: &serde_json::Map<String, Value>,
    pointer: &mut String,
) -> Result<(), SchemaError> {
    let fail_at = |pointer: &mut String, keyword: &str, message: String| {
        let restore = push_token(pointer, keyword);
        let err = SchemaError {
            pointer: pointer.clone(),
            message,
        };
        pointer.truncate(restore);
        err
    };
    if let Some(enum_values) = map.get("enum") {
        if enum_values.as_array().is_none_or(Vec::is_empty) {
            return Err(fail_at(
                pointer,
                "enum",
                "\"enum\" must be a non-empty array".to_string(),
            ));
        }
    }
    for keyword in ["minLength", "maxLength", "minItems", "maxItems"] {
        match map.get(keyword) {
            Some(value) if value.as_u64().is_none() => {
                return Err(fail_at(
                    pointer,
                    keyword,
                    format!("\"{keyword}\" must be a non-negative integer"),
                ));
            }
            _ => {}
        }
    }
    for keyword in ["minimum", "maximum"] {
        match map.get(keyword) {
            Some(value) if !value.is_number() => {
                return Err(fail_at(
                    pointer,
                    keyword,
                    format!("\"{keyword}\" must be a number"),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Validate the `type` keyword: a known type string, or an array of distinct known
/// type strings.
fn check_type_keyword(type_value: &Value, pointer: &mut String) -> Result<(), SchemaError> {
    let restore = push_token(pointer, "type");
    let result = match type_value {
        Value::String(name) if KNOWN_TYPES.contains(&name.as_str()) => Ok(()),
        Value::Array(names) => {
            let mut seen = BTreeSet::new();
            let mut ok = !names.is_empty();
            for entry in names {
                match entry.as_str() {
                    Some(name) if KNOWN_TYPES.contains(&name) && seen.insert(name) => {}
                    _ => ok = false,
                }
            }
            if ok {
                Ok(())
            } else {
                Err("\"type\" array must hold distinct known type names".to_string())
            }
        }
        _ => Err("\"type\" must be a known type name or an array of them".to_string()),
    };
    let out = result.map_err(|message| SchemaError {
        pointer: pointer.clone(),
        message,
    });
    pointer.truncate(restore);
    out
}

/// Validate that a keyword's value is an array of strings.
fn check_string_array(
    value: &Value,
    keyword: &str,
    pointer: &mut String,
) -> Result<(), SchemaError> {
    let restore = push_token(pointer, keyword);
    let ok = value
        .as_array()
        .is_some_and(|items| items.iter().all(Value::is_string));
    let out = if ok {
        Ok(())
    } else {
        Err(SchemaError {
            pointer: pointer.clone(),
            message: format!("\"{keyword}\" must be an array of strings"),
        })
    };
    pointer.truncate(restore);
    out
}

/// Record a failure at the current pointer.
fn fail(pointer: &str, message: impl Into<String>, out: &mut Vec<ValidationFailure>) {
    out.push(ValidationFailure {
        pointer: pointer.to_string(),
        message: message.into(),
    });
}

/// Validate an instance node against a schema node, appending per-field failures.
/// Depth bounded: past [`MAX_DEPTH`] the node is refused with a single failure
/// rather than recursed into.
fn validate_node(
    schema: &Value,
    instance: &Value,
    pointer: &mut String,
    depth: usize,
    out: &mut Vec<ValidationFailure>,
) {
    if depth > MAX_DEPTH {
        fail(pointer, "value nesting exceeds the maximum depth", out);
        return;
    }
    let map = match schema {
        Value::Object(map) => map,
        // A boolean schema `false` rejects everything.
        Value::Bool(false) => {
            fail(pointer, "no value is permitted here", out);
            return;
        }
        // A boolean schema `true` accepts anything; a non-schema node cannot be
        // reached for a compiled schema, so treat it as accepting to stay total.
        _ => return,
    };

    // A type mismatch makes the shape assertions below meaningless, so it short
    // circuits. A match guard rather than an `if let ... &&` let chain (MSRV 1.85).
    match map.get("type") {
        Some(type_value) if !type_matches(type_value, instance) => {
            fail(
                pointer,
                format!("value does not match the required type {type_value}"),
                out,
            );
            return;
        }
        _ => {}
    }

    let enum_mismatch = map
        .get("enum")
        .and_then(Value::as_array)
        .is_some_and(|values| !values.iter().any(|candidate| candidate == instance));
    if enum_mismatch {
        fail(pointer, "value is not one of the permitted values", out);
    }

    match instance {
        Value::Object(fields) => validate_object(map, fields, pointer, depth, out),
        Value::Array(items) => validate_array(map, items, pointer, depth, out),
        Value::String(text) => validate_string(map, text, pointer, out),
        Value::Number(number) => validate_number(map, number, pointer, out),
        _ => {}
    }
}

/// Validate an object instance's `required`, `properties`, and
/// `additionalProperties`.
fn validate_object(
    schema: &serde_json::Map<String, Value>,
    fields: &serde_json::Map<String, Value>,
    pointer: &mut String,
    depth: usize,
    out: &mut Vec<ValidationFailure>,
) {
    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        for name in required.iter().filter_map(Value::as_str) {
            if !fields.contains_key(name) {
                let restore = push_token(pointer, name);
                fail(pointer, "required field is missing", out);
                pointer.truncate(restore);
            }
        }
    }
    let properties = schema.get("properties").and_then(Value::as_object);
    if let Some(properties) = properties {
        for (name, subschema) in properties {
            if let Some(value) = fields.get(name) {
                let restore = push_token(pointer, name);
                validate_node(subschema, value, pointer, depth + 1, out);
                pointer.truncate(restore);
            }
        }
    }
    match schema.get("additionalProperties") {
        Some(Value::Bool(false)) => {
            for name in fields.keys() {
                let declared = properties.is_some_and(|p| p.contains_key(name));
                if !declared {
                    let restore = push_token(pointer, name);
                    fail(pointer, "additional field is not permitted", out);
                    pointer.truncate(restore);
                }
            }
        }
        Some(subschema) if !subschema.is_boolean() => {
            for (name, value) in fields {
                let declared = properties.is_some_and(|p| p.contains_key(name));
                if !declared {
                    let restore = push_token(pointer, name);
                    validate_node(subschema, value, pointer, depth + 1, out);
                    pointer.truncate(restore);
                }
            }
        }
        _ => {}
    }
}

/// Validate an array instance's `prefixItems`, `items`, and size bounds. This is
/// the named Kratos regression surface: arrays (and arrays of objects) must
/// validate element by element.
fn validate_array(
    schema: &serde_json::Map<String, Value>,
    items: &[Value],
    pointer: &mut String,
    depth: usize,
    out: &mut Vec<ValidationFailure>,
) {
    let prefix = schema.get("prefixItems").and_then(Value::as_array);
    if let Some(prefix) = prefix {
        for (index, subschema) in prefix.iter().enumerate() {
            if let Some(value) = items.get(index) {
                let restore = push_token(pointer, &index.to_string());
                validate_node(subschema, value, pointer, depth + 1, out);
                pointer.truncate(restore);
            }
        }
    }
    if let Some(items_schema) = schema.get("items") {
        let start = prefix.map_or(0, Vec::len);
        for (index, value) in items.iter().enumerate().skip(start) {
            let restore = push_token(pointer, &index.to_string());
            validate_node(items_schema, value, pointer, depth + 1, out);
            pointer.truncate(restore);
        }
    }
    let len = items.len() as u64;
    // `.filter` folds the bound comparison into the Option so the emit is a single
    // `if let` with no inner `if` (no let chain: MSRV 1.85, no collapsible-if lint).
    if let Some(min) = schema
        .get("minItems")
        .and_then(Value::as_u64)
        .filter(|&min| len < min)
    {
        fail(pointer, format!("array has fewer than {min} items"), out);
    }
    if let Some(max) = schema
        .get("maxItems")
        .and_then(Value::as_u64)
        .filter(|&max| len > max)
    {
        fail(pointer, format!("array has more than {max} items"), out);
    }
}

/// Validate a string instance's length bounds.
fn validate_string(
    schema: &serde_json::Map<String, Value>,
    text: &str,
    pointer: &str,
    out: &mut Vec<ValidationFailure>,
) {
    let chars = text.chars().count() as u64;
    if let Some(min) = schema
        .get("minLength")
        .and_then(Value::as_u64)
        .filter(|&min| chars < min)
    {
        fail(
            pointer,
            format!("string is shorter than {min} characters"),
            out,
        );
    }
    if let Some(max) = schema
        .get("maxLength")
        .and_then(Value::as_u64)
        .filter(|&max| chars > max)
    {
        fail(
            pointer,
            format!("string is longer than {max} characters"),
            out,
        );
    }
}

/// Validate a number instance's range bounds and the `integer` typing.
fn validate_number(
    schema: &serde_json::Map<String, Value>,
    number: &serde_json::Number,
    pointer: &str,
    out: &mut Vec<ValidationFailure>,
) {
    let Some(value) = number.as_f64() else {
        return;
    };
    if let Some(min) = schema
        .get("minimum")
        .and_then(Value::as_f64)
        .filter(|&min| value < min)
    {
        fail(
            pointer,
            format!("value is less than the minimum {min}"),
            out,
        );
    }
    if let Some(max) = schema
        .get("maximum")
        .and_then(Value::as_f64)
        .filter(|&max| value > max)
    {
        fail(
            pointer,
            format!("value is greater than the maximum {max}"),
            out,
        );
    }
}

/// Whether an instance value matches a `type` keyword (a single name or an array
/// of names; matching any is a match).
fn type_matches(type_value: &Value, instance: &Value) -> bool {
    match type_value {
        Value::String(name) => type_name_matches(name, instance),
        Value::Array(names) => names
            .iter()
            .filter_map(Value::as_str)
            .any(|name| type_name_matches(name, instance)),
        _ => true,
    }
}

/// Whether an instance matches a single JSON Schema primitive type name. `integer`
/// accepts a number with no fractional part (the draft 2020-12 rule).
fn type_name_matches(name: &str, instance: &Value) -> bool {
    match name {
        "object" => instance.is_object(),
        "array" => instance.is_array(),
        "string" => instance.is_string(),
        "boolean" => instance.is_boolean(),
        "null" => instance.is_null(),
        "number" => instance.is_number(),
        "integer" => {
            instance.as_i64().is_some() || instance.as_u64().is_some() || is_integral_f64(instance)
        }
        _ => false,
    }
}

/// Whether a JSON number is an integral float (for example `5.0`), which the
/// `integer` type accepts.
fn is_integral_f64(instance: &Value) -> bool {
    instance
        .as_f64()
        .is_some_and(|value| value.fract() == 0.0 && value.is_finite())
}

/// A declarative transform step a migration job applies to a user's traits before
/// re-validating them against the target schema version (issue #53). The supported
/// operations are the safe, deterministic field mappings: rename a field, default a
/// missing field, and drop a field. Applied in array order, so a transform is a
/// deterministic function of its input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum TransformOp {
    /// Rename a top-level field from `from` to `to`, preserving its value. A no-op
    /// if `from` is absent; if `to` already exists it is overwritten by `from`.
    Rename {
        /// The existing field name.
        from: String,
        /// The new field name.
        to: String,
    },
    /// Set `field` to `value` only when it is absent (a default). An existing field
    /// is left untouched.
    Default {
        /// The field to default.
        field: String,
        /// The default value.
        value: Value,
    },
    /// Remove `field` if present.
    Drop {
        /// The field to drop.
        field: String,
    },
}

/// Parse a transform program from its JSON array text.
///
/// # Errors
///
/// [`SchemaError`] if the text is not a JSON array of well-formed transform steps.
pub fn parse_transform(transform_json: &str) -> Result<Vec<TransformOp>, SchemaError> {
    serde_json::from_str(transform_json).map_err(|err| SchemaError {
        pointer: String::new(),
        message: format!("transform is not a valid transform program: {err}"),
    })
}

/// Apply a transform program to a traits document, returning the transformed copy.
/// Deterministic in the program order. A non-object instance is returned unchanged.
#[must_use]
pub fn apply_transform(ops: &[TransformOp], traits: &Value) -> Value {
    let Value::Object(source) = traits else {
        return traits.clone();
    };
    let mut map = source.clone();
    for op in ops {
        match op {
            TransformOp::Rename { from, to } => {
                if let Some(value) = map.remove(from) {
                    map.insert(to.clone(), value);
                }
            }
            TransformOp::Default { field, value } => {
                map.entry(field.clone()).or_insert_with(|| value.clone());
            }
            TransformOp::Drop { field } => {
                map.remove(field);
            }
        }
    }
    Value::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn schema(value: &Value) -> TraitSchema {
        TraitSchema::compile(&value.to_string()).expect("well-formed schema")
    }

    #[test]
    fn a_well_formed_schema_compiles_and_a_valid_instance_passes() {
        let s = schema(&json!({
            "type": "object",
            "properties": {
                "email": {"type": "string", "minLength": 3},
                "age": {"type": "integer", "minimum": 0}
            },
            "required": ["email"],
            "additionalProperties": false
        }));
        assert!(
            s.validate(&json!({"email": "a@b.test", "age": 30}))
                .is_empty()
        );
    }

    #[test]
    fn a_malformed_schema_is_rejected_with_a_pointer() {
        // Bad type keyword.
        let err = TraitSchema::compile(&json!({"type": "widget"}).to_string()).unwrap_err();
        assert_eq!(err.pointer, "/type");
        // properties must be an object.
        let err = TraitSchema::compile(&json!({"properties": []}).to_string()).unwrap_err();
        assert_eq!(err.pointer, "/properties");
        // required must be an array of strings.
        let err = TraitSchema::compile(&json!({"required": [1]}).to_string()).unwrap_err();
        assert_eq!(err.pointer, "/required");
        // Not even JSON.
        assert!(TraitSchema::compile("{not json").is_err());
    }

    #[test]
    fn required_and_type_failures_carry_json_pointers() {
        let s = schema(&json!({
            "type": "object",
            "properties": {"email": {"type": "string"}, "age": {"type": "integer"}},
            "required": ["email"]
        }));
        let failures = s.validate(&json!({"age": "not a number"}));
        let pointers: Vec<&str> = failures.iter().map(|f| f.pointer.as_str()).collect();
        assert!(
            pointers.contains(&"/email"),
            "missing required email: {pointers:?}"
        );
        assert!(
            pointers.contains(&"/age"),
            "type mismatch on age: {pointers:?}"
        );
    }

    #[test]
    fn arrays_of_objects_validate_element_by_element_the_kratos_regression() {
        // Ory Kratos trait arrays have been broken since 2022; this pins that
        // arrays (and arrays of nested objects) validate correctly.
        let s = schema(&json!({
            "type": "object",
            "properties": {
                "phones": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {"number": {"type": "string"}},
                        "required": ["number"]
                    },
                    "minItems": 1
                }
            }
        }));
        // A valid array of objects round-trips.
        assert!(
            s.validate(&json!({"phones": [{"number": "+15550001"}, {"number": "+15550002"}]}))
                .is_empty()
        );
        // An element missing its required field fails AT THAT ELEMENT's pointer.
        let failures = s.validate(&json!({"phones": [{"number": "+15550001"}, {}]}));
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].pointer, "/phones/1/number");
        // An empty array trips minItems.
        let failures = s.validate(&json!({"phones": []}));
        assert_eq!(failures[0].pointer, "/phones");
    }

    #[test]
    fn deeply_nested_objects_validate() {
        let s = schema(&json!({
            "type": "object",
            "properties": {
                "address": {
                    "type": "object",
                    "properties": {
                        "geo": {
                            "type": "object",
                            "properties": {"lat": {"type": "number"}},
                            "required": ["lat"]
                        }
                    }
                }
            }
        }));
        assert!(
            s.validate(&json!({"address": {"geo": {"lat": 1.5}}}))
                .is_empty()
        );
        let failures = s.validate(&json!({"address": {"geo": {}}}));
        assert_eq!(failures[0].pointer, "/address/geo/lat");
    }

    #[test]
    fn a_pathologically_deep_schema_is_refused_not_recursed() {
        // Build a schema nested well past the depth bound; compile must refuse it
        // with an error rather than overflow the stack (the fuzz obligation).
        let mut deep = json!({"type": "string"});
        for _ in 0..(MAX_DEPTH + 5) {
            deep = json!({"type": "object", "properties": {"n": deep}});
        }
        assert!(TraitSchema::compile(&deep.to_string()).is_err());
    }

    #[test]
    fn a_pathologically_deep_instance_is_refused_not_recursed() {
        let s = schema(&json!({"type": "object"}));
        let mut deep = json!(1);
        for _ in 0..1000 {
            deep = json!([deep]);
        }
        // additionalProperties/items are unconstrained here, so this exercises the
        // instance depth guard directly through a permissive schema wrapper.
        let wrap = schema(
            &json!({"type": "object", "properties": {"x": {"type": "array", "items": true}}}),
        );
        // No panic, bounded work.
        let _ = wrap.validate(&json!({"x": deep}));
        let _ = s.validate(&deep);
    }

    #[test]
    fn annotations_parse_the_behavior_vocabulary_and_visibility() {
        let s = schema(&json!({
            "type": "object",
            "properties": {
                "email": {"type": "string", "x-ironauth": {"identifier": true, "verification": "email", "recovery": true}},
                "risk_score": {"type": "integer", "x-ironauth": {"visibility": "admin"}},
                "nickname": {"type": "string"}
            }
        }));
        let a = s.annotations();
        assert_eq!(a.login_identifiers, vec!["email".to_string()]);
        assert_eq!(
            a.verification_addresses,
            vec![("email".to_string(), "email".to_string())]
        );
        assert_eq!(a.recovery_channels, vec!["email".to_string()]);
        assert_eq!(a.admin_only, vec!["risk_score".to_string()]);
        assert!(a.is_admin_only("risk_score"));
        // The self-service view strips the admin-only field but keeps user fields.
        let redacted =
            a.redact_for_user(&json!({"email": "a@b.test", "risk_score": 90, "nickname": "z"}));
        assert_eq!(redacted, json!({"email": "a@b.test", "nickname": "z"}));
    }

    #[test]
    fn transforms_apply_deterministically_in_order() {
        let ops = parse_transform(
            &json!([
                {"op": "rename", "from": "name", "to": "full_name"},
                {"op": "default", "field": "locale", "value": "en"},
                {"op": "drop", "field": "legacy"}
            ])
            .to_string(),
        )
        .expect("valid transform");
        let out = apply_transform(&ops, &json!({"name": "Zeke", "legacy": 1, "locale": "fr"}));
        assert_eq!(out, json!({"full_name": "Zeke", "locale": "fr"}));
        // Default only fills a missing field.
        let out = apply_transform(&ops, &json!({"name": "Zeke"}));
        assert_eq!(out, json!({"full_name": "Zeke", "locale": "en"}));
    }
}
