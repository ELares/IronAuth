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

    /// The INVISIBLE half's mirror image: every admin-only field a SELF-SERVICE
    /// submission NAMES, reported as per-field failures carrying an RFC 6901 JSON
    /// Pointer to the offending top-level field (issue #53).
    ///
    /// [`redact_for_user`](Self::redact_for_user) makes admin-only metadata invisible on
    /// the way OUT; this makes it IMMUTABLE on the way IN. A self-service surface reads a
    /// REDACTED document, so a well-behaved read-modify-write round trip never names an
    /// admin-only field at all: naming one is always an attempt to write metadata the
    /// surface was never shown, whether the value is new, identical, or `null` (an
    /// explicit clear). All three are refused alike, so there is no shape of submission
    /// that can probe an admin-only field's presence or value.
    ///
    /// An empty vector means the submission names none. A NON-OBJECT instance names no
    /// top-level field and so violates nothing HERE. That is not the whole rule and this
    /// function is not where the whole rule lives: a non-object submission also cannot be
    /// PRESERVED into (there is no member to carry an admin-only field onto), so on its own
    /// it would CLEAR admin-only metadata. Nothing in this crate requires a schema to assert
    /// a root `type`, so the schema cannot be relied on to refuse it either (MEASURED: with a
    /// root-`type`-free schema, submitting `[1, 2]` produced zero violations, survived
    /// preservation unchanged, and the write proceeded). The refusal of that shape belongs
    /// with the OTHER half of the class and lives on the write seam
    /// (`TraitWriteVisibility::apply`), which is the one place that can see BOTH the
    /// submission and the existing document.
    #[must_use]
    pub fn self_service_violations(&self, traits: &Value) -> Vec<ValidationFailure> {
        let Value::Object(map) = traits else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for key in map.keys() {
            if self.is_admin_only(key) {
                out.push(ValidationFailure {
                    pointer: format!("/{}", escape_token(key)),
                    message: "admin-only trait cannot be written through a self-service surface"
                        .to_string(),
                });
            }
        }
        out
    }

    /// Carry every admin-only field of `existing` onto `submitted`, so a self-service
    /// write that OMITS admin-only metadata cannot DELETE it (issue #53).
    ///
    /// This is the second half of immutability and the half that is easy to miss.
    /// [`self_service_violations`](Self::self_service_violations) stops a self-service
    /// write from SETTING an admin-only field; without this, the same write would still
    /// CLEAR one, because a trait write replaces the whole document and a self-service
    /// caller (reading through [`redact_for_user`](Self::redact_for_user)) never had the
    /// admin-only fields to send back.
    ///
    /// Call it AFTER the violation check, never before: reinstating the fields first
    /// would make every submission look like it named them.
    ///
    /// A non-object on either side carries nothing (there is no top-level field to carry).
    pub fn preserve_admin_only(&self, submitted: &mut Value, existing: &Value) {
        let Some(existing_map) = existing.as_object() else {
            return;
        };
        let Some(target) = submitted.as_object_mut() else {
            return;
        };
        for (key, value) in existing_map {
            if self.is_admin_only(key) {
                target.insert(key.clone(), value.clone());
            }
        }
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
        check_schema_wellformed(&root, &mut String::new(), 0, true)?;
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

    /// Resolve an RFC 6901 JSON Pointer into the compiled schema's `properties`
    /// tree, returning the SUB-SCHEMA for that trait path (issue #87, landing on the
    /// #53 trait-schema surface). The pointer is the SAME instance pointer a
    /// [`ValidationFailure`] carries: each object-step token descends through
    /// `properties`, each array-index token descends through `prefixItems` (by index)
    /// or the single `items` schema, so a signup form field that names a trait path
    /// resolves to exactly the sub-schema the validator applies at that location.
    ///
    /// Returns [`None`] when the pointer is empty (a field must name a real trait) or
    /// names a path that does not exist in this schema, which is precisely the
    /// "nonexistent trait path" a form write is rejected for. Pure and deterministic:
    /// it only reads the compiled document.
    #[must_use]
    pub fn subschema_at(&self, pointer: &str) -> Option<&Value> {
        // The empty pointer is the document root, not a trait path; a form field must
        // name a real trait, so it does not resolve.
        if pointer.is_empty() {
            return None;
        }
        let mut current = &self.root;
        // RFC 6901: a non-empty pointer is a run of `/`-prefixed reference tokens.
        for raw_token in pointer.split('/').skip(1) {
            let token = unescape_token(raw_token);
            current = descend_subschema(current, &token)?;
        }
        Some(current)
    }
}

/// Descend one RFC 6901 reference token into a schema node, returning the child
/// sub-schema (issue #87). A property name resolves through `properties` (taking
/// precedence, so a property literally named like a number is still found by name);
/// an array index resolves through `prefixItems` at that index, else the single
/// `items` schema. Any other token does not resolve.
fn descend_subschema<'a>(schema: &'a Value, token: &str) -> Option<&'a Value> {
    let object = schema.as_object()?;
    if let Some(child) = object
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|props| props.get(token))
    {
        return Some(child);
    }
    if let Ok(index) = token.parse::<usize>() {
        if let Some(child) = object
            .get("prefixItems")
            .and_then(Value::as_array)
            .and_then(|prefix| prefix.get(index))
        {
            return Some(child);
        }
        // A single-schema `items` applies to every element past the prefix. A boolean
        // `items` (accept / reject everything) is not a descendable sub-schema.
        match object.get("items") {
            Some(items) if !items.is_boolean() => return Some(items),
            _ => {}
        }
    }
    None
}

/// Reverse an RFC 6901 reference-token escape: `~1` decodes to `/` and `~0` to `~`.
/// The `~1`-before-`~0` order is mandated by RFC 6901 so an escaped `~1` sequence is
/// never mis-decoded.
fn unescape_token(token: &str) -> String {
    token.replace("~1", "/").replace("~0", "~")
}

/// Why a signup form rule WIDENS the trait sub-schema it must narrow (issue #87). It
/// names the offending keyword (and a pointer to it within the rule), never a value,
/// so a rejection is operator-safe and carries no trait data. The closed narrowing
/// vocabulary is `type`, `enum`, `minLength`, `maxLength`, `minItems`, `maxItems`,
/// `minimum`, `maximum` (plus `required`, which can only tighten); any other keyword
/// on a form rule cannot be proven to narrow and is reported here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NarrowingViolation {
    /// An RFC 6901 JSON Pointer to the offending keyword WITHIN the rule object (for
    /// example `/minLength`). Combined by the caller with the field's trait pointer to
    /// name the exact rule location.
    pub pointer: String,
    /// The offending keyword (for example `minLength`). Never a value.
    pub keyword: String,
}

/// Whether a signup form `rule` is a STRUCTURAL SUBSET of a `trait_subschema` over
/// the closed keyword vocabulary (issue #87, landing on the #53 surface): the form
/// may only TIGHTEN the trait's constraint, never widen it.
///
/// A rule narrows when, for every keyword it carries:
///
/// - `type`: the form's type set is a subset of the trait's (a trait with no `type`
///   permits any type, so any form type narrows it);
/// - `enum`: every form enum member is in the trait's enum (introducing an enum where
///   the trait has none is narrowing);
/// - `minLength` / `minItems` / `minimum`: the form's lower bound is `>=` the trait's
///   (a tighter floor; a trait with no such bound is widened by nothing);
/// - `maxLength` / `maxItems` / `maximum`: the form's upper bound is `<=` the trait's
///   (a tighter ceiling); and
/// - `required`: always narrowing (a form may require a trait the schema does not).
///
/// A rule that RELAXES any bound, names an enum member the trait does not permit,
/// broadens the type, or carries any keyword outside the closed vocabulary is a
/// widening and returns [`NarrowingViolation`]. Pure and deterministic; a violation
/// names the keyword, never a value.
///
/// # Errors
///
/// [`NarrowingViolation`] naming the first widening keyword (iterated in the rule's
/// object key order, which serde keeps sorted, so the result is deterministic).
pub fn narrows(form_rule: &Value, trait_subschema: &Value) -> Result<(), NarrowingViolation> {
    // An absent rule (null) tightens nothing and narrows trivially. A rule that is
    // neither null nor an object is malformed and cannot be proven to narrow, so it is
    // refused, fail closed like every keyword handler below.
    let rule = match form_rule {
        Value::Null => return Ok(()),
        Value::Object(map) => map,
        _ => return Err(narrowing_violation("rules")),
    };
    for (keyword, value) in rule {
        match keyword.as_str() {
            "type" => check_type_narrows(value, trait_subschema, keyword)?,
            "enum" => check_enum_narrows(value, trait_subschema, keyword)?,
            "minLength" | "minItems" => {
                check_integer_bound(keyword, value, trait_subschema, Bound::Lower)?;
            }
            "maxLength" | "maxItems" => {
                check_integer_bound(keyword, value, trait_subschema, Bound::Upper)?;
            }
            "minimum" => check_number_bound(keyword, value, trait_subschema, Bound::Lower)?,
            "maximum" => check_number_bound(keyword, value, trait_subschema, Bound::Upper)?,
            // A form may REQUIRE a trait the schema does not; that only tightens.
            "required" => {}
            // Any other keyword cannot be proven to narrow the trait, so it is refused.
            other => return Err(narrowing_violation(other)),
        }
    }
    Ok(())
}

/// Which end of a bound a keyword tightens: a lower bound tightens by growing, an
/// upper bound tightens by shrinking.
#[derive(Clone, Copy)]
enum Bound {
    Lower,
    Upper,
}

/// Build a [`NarrowingViolation`] for `keyword`, pointing at it within the rule.
fn narrowing_violation(keyword: &str) -> NarrowingViolation {
    NarrowingViolation {
        pointer: format!("/{}", escape_token(keyword)),
        keyword: keyword.to_string(),
    }
}

/// The set of primitive type names a `type` keyword denotes (a single name or an
/// array of names). A non-string, non-array value denotes the empty set.
fn type_name_set(type_value: &Value) -> BTreeSet<&str> {
    match type_value {
        Value::String(name) => std::iter::once(name.as_str()).collect(),
        Value::Array(names) => names.iter().filter_map(Value::as_str).collect(),
        _ => BTreeSet::new(),
    }
}

/// The `type` keyword narrows when the form's type set is a subset of the trait's. A
/// trait with no `type` permits every type, so any form type narrows it.
fn check_type_narrows(
    form_type: &Value,
    trait_subschema: &Value,
    keyword: &str,
) -> Result<(), NarrowingViolation> {
    let form = type_name_set(form_type);
    // A malformed form `type` (not a string, not an array of type names, or an array with
    // no usable name) denotes the empty set, which would be a subset of anything. That
    // cannot be proven to narrow, so it is refused, fail closed like the other keywords.
    if form.is_empty() {
        return Err(narrowing_violation(keyword));
    }
    let Some(trait_type) = trait_subschema.get("type") else {
        // The trait permits every type, so a well formed form type narrows it.
        return Ok(());
    };
    let trait_set = type_name_set(trait_type);
    if form.is_subset(&trait_set) {
        Ok(())
    } else {
        Err(narrowing_violation(keyword))
    }
}

/// The `enum` keyword narrows when every form enum member is one the trait permits.
/// A trait with no `enum` permits any value the type allows, so INTRODUCING an enum is
/// narrowing.
fn check_enum_narrows(
    form_enum: &Value,
    trait_subschema: &Value,
    keyword: &str,
) -> Result<(), NarrowingViolation> {
    let Some(form_values) = form_enum.as_array() else {
        // A malformed form enum cannot be proven to narrow.
        return Err(narrowing_violation(keyword));
    };
    let Some(trait_values) = trait_subschema.get("enum").and_then(Value::as_array) else {
        return Ok(());
    };
    for member in form_values {
        if !trait_values.iter().any(|candidate| candidate == member) {
            return Err(narrowing_violation(keyword));
        }
    }
    Ok(())
}

/// An integer length / size bound (`minLength` / `maxLength` / `minItems` /
/// `maxItems`) narrows when a LOWER bound is `>=` the trait's and an UPPER bound is
/// `<=` the trait's. A trait without the bound is tightened by any form bound; a
/// malformed (non-integer) form bound cannot be proven to narrow.
fn check_integer_bound(
    keyword: &str,
    form_value: &Value,
    trait_subschema: &Value,
    bound: Bound,
) -> Result<(), NarrowingViolation> {
    let Some(form) = form_value.as_u64() else {
        return Err(narrowing_violation(keyword));
    };
    let Some(trait_bound) = trait_subschema.get(keyword).and_then(Value::as_u64) else {
        return Ok(());
    };
    let narrows = match bound {
        Bound::Lower => form >= trait_bound,
        Bound::Upper => form <= trait_bound,
    };
    if narrows {
        Ok(())
    } else {
        Err(narrowing_violation(keyword))
    }
}

/// A numeric range bound (`minimum` / `maximum`) narrows when a LOWER bound is `>=`
/// the trait's and an UPPER bound is `<=` the trait's. A trait without the bound is
/// tightened by any form bound; a malformed (non-numeric) form bound cannot be proven
/// to narrow.
fn check_number_bound(
    keyword: &str,
    form_value: &Value,
    trait_subschema: &Value,
    bound: Bound,
) -> Result<(), NarrowingViolation> {
    let Some(form) = form_value.as_f64() else {
        return Err(narrowing_violation(keyword));
    };
    let Some(trait_bound) = trait_subschema.get(keyword).and_then(Value::as_f64) else {
        return Ok(());
    };
    let narrows = match bound {
        Bound::Lower => form >= trait_bound,
        Bound::Upper => form <= trait_bound,
    };
    if narrows {
        Ok(())
    } else {
        Err(narrowing_violation(keyword))
    }
}

/// Escape a single reference token for an RFC 6901 JSON Pointer: `~` becomes `~0`
/// and `/` becomes `~1`, so a token containing either character is unambiguous.
fn escape_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

/// Push a reference token onto a JSON Pointer, returning the length to truncate
/// back to afterwards (so a single mutable `String` walks the whole tree).
pub(crate) fn push_pointer_token(pointer: &mut String, token: &str) {
    push_token(pointer, token);
}

/// Push a reference token onto a JSON Pointer, returning the length to truncate back to.
fn push_token(pointer: &mut String, token: &str) -> usize {
    let restore = pointer.len();
    pointer.push('/');
    pointer.push_str(&escape_token(token));
    restore
}

/// Check that a schema document (or sub-schema) is well formed within the
/// supported vocabulary and depth bound.
///
/// `annotatable` is true for the document ROOT and for the direct children of the ROOT
/// `properties`, which are the sub-schemas [`TraitSchema::annotations`] actually reads plus
/// the position a lone sub-schema occupies when it is compiled on its own. See the
/// [`ANNOTATION_KEYWORD`] check below for why anywhere DEEPER is a hard refusal, and why the
/// root is not.
fn check_schema_wellformed(
    schema: &Value,
    pointer: &mut String,
    depth: usize,
    annotatable: bool,
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

    // `x-ironauth` is read ONLY off the ROOT `properties` ([`TraitSchema::annotations`]), so
    // the SAME keyword one level down is INERT: it compiles, it activates, and it enforces
    // nothing. That is a tolerable shape for a purely documentary keyword and NOT a tolerable
    // shape for `visibility`, which issue #53 turns into a security boundary. MEASURED on the
    // pre-fix tree: with `address: {properties: {secret: {x-ironauth: {visibility: admin}}}}`,
    // a self-service write OVERWROTE `address.secret` with an attacker string and a later
    // omission CLEARED it, while the root-level `risk_score` control was correctly preserved by
    // the same write. An operator reading that schema would believe the nested field was
    // protected. Refuse it LOUDLY instead, naming the offending pointer, so the belief and the
    // behavior cannot diverge.
    //
    // The document ROOT is annotatable, and that is not a loophole. A sub-schema of a compiled
    // trait schema is legitimately COMPILED ON ITS OWN elsewhere in the tree (the signup-field
    // path's `node_accepts` compiles the field's sub-schema to validate one submitted value
    // against it), and a top-level trait's sub-schema is precisely a document whose ROOT
    // carries the annotation. MEASURED: refusing the root too broke three signup-field unit
    // tests, because the fail-closed `Err(_) => false` in that helper turned every annotated
    // field's valid value into an invalid-format failure. Refusing the root would therefore
    // trade a misleading annotation for a broken one, which is worse. It also costs nothing:
    // the position this rule protects is BELOW a root `properties`, and a full trait schema is
    // always compiled from its own root, so a nested annotation is still refused there.
    if !annotatable && map.contains_key(ANNOTATION_KEYWORD) {
        let restore = push_token(pointer, ANNOTATION_KEYWORD);
        let err = SchemaError {
            pointer: pointer.clone(),
            message: format!(
                "\"{ANNOTATION_KEYWORD}\" is only read on a TOP-LEVEL property of the schema \
                 root, so it is refused here rather than accepted and ignored"
            ),
        };
        pointer.truncate(restore);
        return Err(err);
    }

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
            // A ROOT property (and only a root property) is where an annotation is read.
            check_schema_wellformed(subschema, pointer, depth + 1, depth == 0)?;
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
            check_schema_wellformed(additional, pointer, depth + 1, false)?;
            pointer.truncate(restore);
        }
        _ => {}
    }
    if let Some(items) = map.get("items") {
        let restore = push_token(pointer, "items");
        check_schema_wellformed(items, pointer, depth + 1, false)?;
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
            check_schema_wellformed(subschema, pointer, depth + 1, false)?;
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

    /// A schema whose `risk_score` is admin-only and whose `nickname` is not, plus an
    /// admin-only field whose NAME needs RFC 6901 escaping, so the pointer the refusal
    /// reports is exercised rather than assumed.
    fn visibility_annotations() -> TraitAnnotations {
        schema(&json!({
            "type": "object",
            "properties": {
                "nickname": {"type": "string"},
                "risk_score": {"type": "integer", "x-ironauth": {"visibility": "admin"}},
                "ops/note~1": {"type": "string", "x-ironauth": {"visibility": "admin"}}
            }
        }))
        .annotations()
    }

    #[test]
    fn a_self_service_submission_naming_an_admin_only_trait_is_refused_per_field() {
        let a = visibility_annotations();
        // A submission touching only user-visible fields names no admin-only trait.
        assert!(
            a.self_service_violations(&json!({"nickname": "z"}))
                .is_empty()
        );
        // SETTING an admin-only field is refused, with an RFC 6901 pointer at it.
        let set = a.self_service_violations(&json!({"nickname": "z", "risk_score": 0}));
        assert_eq!(set.len(), 1, "{set:?}");
        assert_eq!(set[0].pointer, "/risk_score");
        assert!(
            set[0].message.contains("admin-only"),
            "the reason names the class, not the value: {}",
            set[0].message
        );
        // CLEARING it explicitly (an unconditional `null`) is the same refusal: the two
        // shapes must not be distinguishable, or the refusal is a presence oracle.
        let cleared = a.self_service_violations(&json!({"risk_score": null}));
        assert_eq!(cleared.len(), 1, "{cleared:?}");
        assert_eq!(cleared[0].pointer, "/risk_score");
        assert_eq!(cleared[0], set[0], "set and clear are refused identically");
        // The pointer is RFC 6901 ESCAPED: `~` is `~0` and `/` is `~1`, in that order.
        let escaped = a.self_service_violations(&json!({"ops/note~1": "x"}));
        assert_eq!(escaped.len(), 1, "{escaped:?}");
        assert_eq!(escaped[0].pointer, "/ops~1note~01");
        // Every offending field is reported, not merely the first.
        let both = a.self_service_violations(&json!({"risk_score": 1, "ops/note~1": "x"}));
        assert_eq!(both.len(), 2, "{both:?}");
        // A non-object names no top-level field.
        assert!(a.self_service_violations(&json!([1, 2])).is_empty());
    }

    #[test]
    fn a_self_service_write_omitting_an_admin_only_trait_cannot_clear_it() {
        let a = visibility_annotations();
        let existing = json!({"nickname": "old", "risk_score": 90, "ops/note~1": "watch"});
        // The self-service caller read a REDACTED document, so its write back omits every
        // admin-only field. Preservation carries them over verbatim.
        let mut submitted = json!({"nickname": "new"});
        a.preserve_admin_only(&mut submitted, &existing);
        assert_eq!(
            submitted,
            json!({"nickname": "new", "risk_score": 90, "ops/note~1": "watch"}),
            "the user field is updated and both admin-only fields survive"
        );
        // Preservation never invents a field the identity did not already carry.
        let mut fresh = json!({"nickname": "n"});
        a.preserve_admin_only(&mut fresh, &json!({"nickname": "old"}));
        assert_eq!(fresh, json!({"nickname": "n"}));
        // It never carries a USER-visible field: the submission stays authoritative for
        // everything it is allowed to write, so omitting `nickname` still clears it.
        let mut dropped = json!({});
        a.preserve_admin_only(&mut dropped, &existing);
        assert_eq!(dropped, json!({"risk_score": 90, "ops/note~1": "watch"}));
        // A non-object on either side carries nothing and does not panic.
        let mut scalar = json!("x");
        a.preserve_admin_only(&mut scalar, &existing);
        assert_eq!(scalar, json!("x"));
        let mut target = json!({"nickname": "n"});
        a.preserve_admin_only(&mut target, &json!(7));
        assert_eq!(target, json!({"nickname": "n"}));
    }

    #[test]
    fn an_annotation_anywhere_but_a_top_level_property_is_refused_by_name() {
        // The ONE position that is read, and therefore the one that compiles: a direct
        // child of the root `properties`.
        assert!(
            TraitSchema::compile(
                &json!({
                    "type": "object",
                    "properties": {
                        "risk_score": {"type": "integer", "x-ironauth": {"visibility": "admin"}}
                    }
                })
                .to_string()
            )
            .is_ok()
        );

        // A NESTED property. This is the shape that made the annotation a lie: it compiled,
        // it activated, and it enforced NOTHING, because `annotations()` reads only the root
        // `properties`. MEASURED on the pre-fix tree: a self-service write overwrote
        // `address.secret` with an attacker string and a later omission CLEARED it, while
        // the root-level control in the SAME write was correctly preserved.
        let nested = TraitSchema::compile(
            &json!({
                "type": "object",
                "properties": {
                    "address": {
                        "type": "object",
                        "properties": {
                            "secret": {"type": "string", "x-ironauth": {"visibility": "admin"}}
                        }
                    }
                }
            })
            .to_string(),
        )
        .expect_err("a nested annotation must be refused, not silently ignored");
        assert_eq!(
            nested.pointer, "/properties/address/properties/secret/x-ironauth",
            "the refusal names the offending LOCATION, so an operator can find it: {nested}"
        );
        assert!(
            nested.message.contains("x-ironauth"),
            "the reason names the keyword: {}",
            nested.message
        );

        // Inside an ARRAY item: same verdict, different descent.
        let in_items = TraitSchema::compile(
            &json!({
                "type": "object",
                "properties": {
                    "phones": {
                        "type": "array",
                        "items": {"type": "string", "x-ironauth": {"visibility": "admin"}}
                    }
                }
            })
            .to_string(),
        )
        .expect_err("an annotation inside `items` must be refused");
        assert_eq!(in_items.pointer, "/properties/phones/items/x-ironauth");

        // At the ROOT itself: PERMITTED, deliberately. A sub-schema of a compiled trait
        // schema is legitimately compiled on its own (the signup-field path does exactly
        // that to validate one submitted value), and a top-level trait's sub-schema is a
        // document whose ROOT carries the annotation. MEASURED: refusing the root broke
        // three `flow::signup_fields` unit tests, because that helper is fail-closed and
        // turned every annotated field's VALID value into an invalid-format failure. The
        // position this rule protects is below a root `properties`, and a full trait schema
        // is always compiled from its own root, so the nested case above is still refused.
        assert!(
            TraitSchema::compile(
                &json!({"type": "string", "x-ironauth": {"visibility": "admin"}}).to_string()
            )
            .is_ok(),
            "a lone sub-schema carrying its own annotation must still compile"
        );
    }

    #[test]
    fn subschema_at_resolves_object_and_array_trait_paths() {
        // issue #87: a trait pointer resolves to the sub-schema the validator applies
        // at that instance location, through nested objects and arrays.
        let s = schema(&json!({
            "type": "object",
            "properties": {
                "email": {"type": "string", "minLength": 3},
                "address": {
                    "type": "object",
                    "properties": {"zip": {"type": "string", "maxLength": 10}}
                },
                "phones": {
                    "type": "array",
                    "items": {"type": "object", "properties": {"number": {"type": "string"}}}
                }
            }
        }));
        assert_eq!(
            s.subschema_at("/email"),
            Some(&json!({"type": "string", "minLength": 3}))
        );
        assert_eq!(
            s.subschema_at("/address/zip"),
            Some(&json!({"type": "string", "maxLength": 10}))
        );
        // An array element resolves through `items`, then its property.
        assert_eq!(
            s.subschema_at("/phones/0/number"),
            Some(&json!({"type": "string"}))
        );
        // A nonexistent path (and the empty pointer) does not resolve.
        assert_eq!(s.subschema_at("/nope"), None);
        assert_eq!(s.subschema_at("/address/missing"), None);
        assert_eq!(s.subschema_at(""), None);
    }

    #[test]
    fn subschema_at_resolves_prefix_items_by_index_and_escaped_tokens() {
        let s = schema(&json!({
            "type": "object",
            "properties": {
                "pair": {
                    "type": "array",
                    "prefixItems": [{"type": "string"}, {"type": "integer"}]
                },
                "a/b": {"type": "boolean"}
            }
        }));
        assert_eq!(s.subschema_at("/pair/0"), Some(&json!({"type": "string"})));
        assert_eq!(s.subschema_at("/pair/1"), Some(&json!({"type": "integer"})));
        // Past the prefix with no `items` schema does not resolve.
        assert_eq!(s.subschema_at("/pair/2"), None);
        // An RFC 6901 escaped `/` (`~1`) in a property name resolves by name.
        assert_eq!(s.subschema_at("/a~1b"), Some(&json!({"type": "boolean"})));
    }

    #[test]
    fn narrows_accepts_every_tightening() {
        // A tighter type (subset), a tighter enum (subset of a value space), tighter
        // lower and upper bounds, an INTRODUCED enum / bound where the trait has none,
        // and a form-level `required` the trait lacks: each narrows.
        let string_trait = json!({"type": "string", "minLength": 2, "maxLength": 20});
        // Same bounds narrow (a subset is reflexive).
        assert!(narrows(&json!({"minLength": 2, "maxLength": 20}), &string_trait).is_ok());
        // Tighter bounds narrow.
        assert!(narrows(&json!({"minLength": 5, "maxLength": 10}), &string_trait).is_ok());
        // Introducing a bound the trait does not carry narrows.
        assert!(narrows(&json!({"minLength": 1}), &json!({"type": "string"})).is_ok());
        // A type subset narrows; a trait with no `type` permits any type.
        assert!(
            narrows(
                &json!({"type": "string"}),
                &json!({"type": ["string", "null"]})
            )
            .is_ok()
        );
        assert!(narrows(&json!({"type": "string"}), &json!({})).is_ok());
        // Introducing an enum where the trait has none narrows.
        assert!(narrows(&json!({"enum": ["a", "b"]}), &json!({"type": "string"})).is_ok());
        // An enum subset of the trait's enum narrows.
        assert!(
            narrows(
                &json!({"enum": ["a"]}),
                &json!({"type": "string", "enum": ["a", "b", "c"]})
            )
            .is_ok()
        );
        // Numeric range tightening narrows; `required` always narrows.
        let num_trait = json!({"type": "integer", "minimum": 0, "maximum": 100});
        assert!(narrows(&json!({"minimum": 10, "maximum": 50}), &num_trait).is_ok());
        assert!(narrows(&json!({"required": ["x"]}), &num_trait).is_ok());
        // Item-count tightening narrows.
        let arr_trait = json!({"type": "array", "minItems": 1, "maxItems": 9});
        assert!(narrows(&json!({"minItems": 2, "maxItems": 5}), &arr_trait).is_ok());
    }

    #[test]
    fn narrows_rejects_every_widening() {
        let string_trait = json!({"type": "string", "minLength": 5, "maxLength": 10});
        // A relaxed lower bound (allows shorter than the trait's floor) widens.
        assert_eq!(
            narrows(&json!({"minLength": 2}), &string_trait)
                .unwrap_err()
                .keyword,
            "minLength"
        );
        // A relaxed upper bound (allows longer than the trait's ceiling) widens.
        assert_eq!(
            narrows(&json!({"maxLength": 50}), &string_trait)
                .unwrap_err()
                .keyword,
            "maxLength"
        );
        // A broader type widens.
        assert_eq!(
            narrows(
                &json!({"type": ["string", "integer"]}),
                &json!({"type": "string"})
            )
            .unwrap_err()
            .keyword,
            "type"
        );
        // An enum member the trait does not permit widens.
        assert_eq!(
            narrows(
                &json!({"enum": ["a", "z"]}),
                &json!({"type": "string", "enum": ["a", "b"]})
            )
            .unwrap_err()
            .keyword,
            "enum"
        );
        // A relaxed numeric lower / upper bound widens.
        let num_trait = json!({"type": "integer", "minimum": 0, "maximum": 100});
        assert_eq!(
            narrows(&json!({"minimum": -5}), &num_trait)
                .unwrap_err()
                .keyword,
            "minimum"
        );
        assert_eq!(
            narrows(&json!({"maximum": 200}), &num_trait)
                .unwrap_err()
                .keyword,
            "maximum"
        );
        // A relaxed item-count bound widens.
        let arr_trait = json!({"type": "array", "minItems": 2, "maxItems": 5});
        assert_eq!(
            narrows(&json!({"maxItems": 50}), &arr_trait)
                .unwrap_err()
                .keyword,
            "maxItems"
        );
        // A keyword outside the closed narrowing vocabulary cannot be proven to narrow.
        let violation = narrows(&json!({"pattern": "^x$"}), &string_trait).unwrap_err();
        assert_eq!(violation.keyword, "pattern");
        assert_eq!(violation.pointer, "/pattern");
        // Fail closed on malformed input: a rule that is not an object, and a `type`
        // keyword that is not a type name or an array of names, cannot be proven to narrow
        // and so are refused (rather than accepted as the empty set, which would widen).
        assert_eq!(
            narrows(&json!("haxor"), &string_trait).unwrap_err().keyword,
            "rules"
        );
        assert_eq!(
            narrows(&json!(5), &string_trait).unwrap_err().keyword,
            "rules"
        );
        assert_eq!(
            narrows(&json!({"type": 5}), &string_trait)
                .unwrap_err()
                .keyword,
            "type"
        );
        assert_eq!(
            narrows(&json!({"type": {}}), &string_trait)
                .unwrap_err()
                .keyword,
            "type"
        );
        // A malformed type is refused EVEN when the trait has no type (nothing to subset).
        assert_eq!(
            narrows(&json!({"type": 5}), &json!({"minLength": 1}))
                .unwrap_err()
                .keyword,
            "type"
        );
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

    /// RFC 6901 escaping, which is order dependent in BOTH directions and silent when it
    /// is wrong.
    ///
    /// Escaping must replace `~` before `/`: doing `/` first produces a `~1` that the `~`
    /// pass then turns into `~01`. Unescaping must replace `~1` before `~0` for the mirror
    /// reason: `~01` becomes `~1` under a `~0`-first pass, and then `/`.
    ///
    /// Both functions are currently correct and neither was tested, which is the state
    /// where somebody tidies the two `replace` calls into a "cleaner" order and nothing
    /// says otherwise. A field named `a/b` would then point at a nested location that does
    /// not exist, and the client would be told its error is somewhere it never sent.
    #[test]
    fn pointer_tokens_round_trip_through_escaping() {
        for token in [
            "plain",
            "",
            "with/slash",
            "with~tilde",
            // The adversarial pair: text that already LOOKS like an escape sequence.
            "~0",
            "~1",
            "~01",
            "a/b~c",
            "///",
            "~~~",
        ] {
            assert_eq!(
                unescape_token(&escape_token(token)),
                token,
                "escaping {token:?} must be reversible"
            );
        }
    }

    #[test]
    fn escaping_replaces_tilde_before_slash() {
        // Pinned directly, not just via the round trip: the wrong order round-trips for
        // some inputs while producing a pointer no other RFC 6901 implementation agrees
        // with, so a reversible-but-nonstandard encoding would slip past the test above.
        assert_eq!(escape_token("a/b"), "a~1b");
        assert_eq!(escape_token("a~b"), "a~0b");
        // The case that separates the two orders. Correct: `~` -> `~0`, then `/` -> `~1`.
        // Wrong: `/` -> `~1`, then that `~` -> `~0`, giving `a~01b`.
        assert_eq!(escape_token("a~/b"), "a~0~1b");
    }

    #[test]
    fn unescaping_replaces_tilde_one_before_tilde_zero() {
        assert_eq!(unescape_token("a~1b"), "a/b");
        assert_eq!(unescape_token("a~0b"), "a~b");
        // The mirror case. Correct: `~1` -> `/` first, so `~01` keeps its `0` and becomes
        // `~1`. Wrong: `~0` -> `~` first turns `~01` into `~1`, which then becomes `/`.
        assert_eq!(unescape_token("~01"), "~1");
    }
}
