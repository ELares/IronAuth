// SPDX-License-Identifier: MIT OR Apache-2.0

//! The declarative claim-mapping EVALUATOR (issue #75, PR C): a pure, I/O-free
//! transform from an upstream's verified claims to an IronAuth identity trait
//! document, with a fail-closed contract.
//!
//! PR A parsed and stored the [`ClaimMapping`](crate::ClaimMapping) SHAPE; this
//! module is its evaluator. It is DECLARATIVE only: it resolves ordered claim-path
//! fallbacks and assembles a trait document, with NO transforms and NO programmable
//! logic (the pre-token hook and the claims-mapping engine are M11, out of scope).
//! It stays PURE (no clock, no entropy, no fetch), so the crate remains fetch-free
//! by construction and the evaluator is exhaustively unit-testable.
//!
//! # Fail-closed provisioning
//!
//! [`evaluate`] returns `Result<TraitDocument, ClaimMappingError>`. On ANY failure
//! (a missing required claim, a malformed subject claim, or a trait-schema
//! type-check failure) it returns `Err` and NO trait document is produced: the
//! federation callback aborts BEFORE any user row is written, so a mapping failure
//! never provisions a partial identity. The document is assembled AND type-checked
//! in full first; only a fully valid document is returned.
//!
//! # The two error classes
//!
//! The error distinguishes WHO is at fault, so an operator can tell a broken mapping
//! from a misbehaving upstream (and issue #76's failure-isolation layer can classify):
//!
//! - [`ClaimMappingError::MappingInvalid`] (maps to
//!   [`ConnectorError::Config`](crate::ConnectorError::Config)): the mapping
//!   DEFINITION is wrong. A resolved value fails the trait schema's type check, or a
//!   rule targets a trait the active schema does not declare, or the scope has no
//!   active schema to validate the mapped traits against. Not retryable: the same
//!   definition fails again until an operator fixes it.
//! - [`ClaimMappingError::UpstreamClaim`] (maps to
//!   [`ConnectorError::UpstreamProtocol`](crate::ConnectorError::UpstreamProtocol)):
//!   the UPSTREAM misbehaved. A required claim is absent, or a claim (the subject) is
//!   malformed. Not retryable at this layer: replaying the exchange yields the same
//!   answer.
//!
//! Both classes carry RFC 6901 JSON POINTERS to the offending trait fields and
//! operator-safe messages, and NEVER a claim VALUE (no PII leaks into an error).

use serde_json::{Map, Value};
use unicode_normalization::UnicodeNormalization;

use crate::error::ConnectorError;
use crate::{ClaimMapping, ClaimRule, EmailSource, Quirks};

/// The trait field whose resolution the `email_source` quirk governs.
const EMAIL_FIELD: &str = "email";

/// The default subject rule when a mapping does not override it: the standard OIDC
/// `sub` claim, required. A federated identity has no meaning without a stable
/// subject.
fn default_subject_rule() -> ClaimRule {
    ClaimRule {
        source: vec!["sub".to_owned()],
        required: true,
    }
}

/// One RFC 6901 pointer failure from a trait-schema type check, mirrored from
/// `ironauth_store::ValidationFailure` WITHOUT a dependency on the store (this crate
/// stays store-free). The federation layer adapts the store's failures into this
/// shape. Carries no claim value, so it is safe to log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraitPointerFailure {
    /// An RFC 6901 JSON Pointer to the failing location in the trait document.
    pub pointer: String,
    /// A stable, operator-safe reason (never the offending value).
    pub message: String,
}

/// The minimal, store-free VIEW of the scope's active trait schema the evaluator
/// needs to type-check an assembled trait document.
///
/// It is a trait (rather than a direct dependency on `ironauth_store::TraitSchema`)
/// so this crate stays pure and store-free: the federation layer implements it over
/// the store's compiled schema, and the evaluator's unit tests implement a tiny fake.
pub trait TraitSchemaView {
    /// Type-check `document` against the active schema, returning every per-field
    /// failure with its RFC 6901 pointer. An empty vector means the document is
    /// valid. Must never echo a claim value into a failure message (no PII).
    fn type_check(&self, document: &Value) -> Vec<TraitPointerFailure>;
}

/// The verified upstream claim SOURCES the evaluator resolves against: the ID-token
/// claims (always present and verified) and, optionally, the `UserInfo` claims.
///
/// A trait rule resolves against the ID token first, then `UserInfo` (the ID token
/// takes precedence); the `email` field's precedence is instead governed by the
/// connector's `email_source` quirk.
#[derive(Debug, Clone, Copy)]
pub struct ClaimSources<'a> {
    /// The verified ID-token claims (always present).
    pub id_token: &'a Map<String, Value>,
    /// The `UserInfo` claims, when the connector fetched them; [`None`] otherwise.
    pub userinfo: Option<&'a Map<String, Value>>,
}

/// The assembled IronAuth identity from a successful claim-mapping evaluation.
///
/// The `subject` is resolved per the mapping's subject rule (defaulting to `sub`).
/// NOTE: the local identity KEY stays the issuer-namespaced `(issuer, sub)` composite
/// the federation layer established; this `subject` is the mapped view, not a change
/// to the identity key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraitDocument {
    /// The resolved upstream subject (per the subject rule; `sub` by default).
    pub subject: String,
    /// The assembled, type-checked trait object (empty when the mapping maps no
    /// traits).
    pub traits: Map<String, Value>,
}

impl TraitDocument {
    /// Whether the mapping produced no trait fields (only a subject). A trait-free
    /// document needs no schema and provisions a minimal identity.
    #[must_use]
    pub fn is_traitless(&self) -> bool {
        self.traits.is_empty()
    }

    /// The trait object as a [`Value`], for serialization or type checking.
    #[must_use]
    pub fn traits_value(&self) -> Value {
        Value::Object(self.traits.clone())
    }
}

/// Why a claim-mapping evaluation failed. `#[non_exhaustive]` so issue #76 can match
/// on it and new classes can be added without a breaking change. Every variant
/// carries operator-safe RFC 6901 pointers and a message, NEVER a claim value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClaimMappingError {
    /// The mapping DEFINITION is wrong: a resolved value fails the trait schema's
    /// type check, a rule targets a trait the schema does not declare, or the scope
    /// has no active schema to validate the mapped traits against. Maps to
    /// [`ConnectorError::Config`]: an operator must fix the definition.
    MappingInvalid {
        /// RFC 6901 pointers to the offending trait fields (empty when the fault is
        /// scope-level, e.g. no active schema).
        pointers: Vec<String>,
        /// An operator-safe description (no claim value).
        message: String,
    },
    /// The UPSTREAM misbehaved: a required claim is absent, or a claim is malformed.
    /// Maps to [`ConnectorError::UpstreamProtocol`]: the upstream sent a well-formed
    /// token missing or malforming a claim the mapping needs.
    UpstreamClaim {
        /// RFC 6901 pointers to the trait fields (or `/subject`) whose required claim
        /// was absent or malformed.
        pointers: Vec<String>,
        /// An operator-safe description (no claim value).
        message: String,
    },
}

impl std::fmt::Display for ClaimMappingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClaimMappingError::MappingInvalid { pointers, message } => {
                write!(f, "claim mapping is invalid: {message}{}", render(pointers))
            }
            ClaimMappingError::UpstreamClaim { pointers, message } => {
                write!(f, "upstream claim problem: {message}{}", render(pointers))
            }
        }
    }
}

impl std::error::Error for ClaimMappingError {}

/// Render a pointer list as a bounded, operator-safe suffix (never a claim value).
fn render(pointers: &[String]) -> String {
    if pointers.is_empty() {
        String::new()
    } else {
        format!(" (at {})", pointers.join(", "))
    }
}

impl From<ClaimMappingError> for ConnectorError {
    /// Fold the two evaluation classes into the stable connector taxonomy issue #76
    /// consumes: a mapping-definition fault is a (non-retryable) `Config` error, and
    /// an upstream claim fault is a (non-retryable) `UpstreamProtocol` error.
    fn from(error: ClaimMappingError) -> Self {
        match &error {
            ClaimMappingError::MappingInvalid { .. } => ConnectorError::Config(error.to_string()),
            ClaimMappingError::UpstreamClaim { .. } => {
                ConnectorError::UpstreamProtocol(error.to_string())
            }
        }
    }
}

/// Evaluate a declarative claim mapping against verified upstream claims, producing a
/// fully assembled and type-checked IronAuth trait document, or a typed error.
///
/// Resolution is declarative: the subject and each trait field resolve their ordered
/// claim-path fallback (the first path that resolves to a non-null value wins). A
/// trait field resolves against the ID token then `UserInfo` (ID token precedence);
/// the `email` field's source order is governed by the connector's `email_source`
/// quirk. A required claim that resolves to nothing fails closed as
/// [`ClaimMappingError::UpstreamClaim`].
///
/// Once every required claim is present, the assembled trait object is type-checked
/// against the scope's active schema (`schema`). A trait-schema failure (a wrong
/// type, a trait the schema does not declare, or an absent active schema when traits
/// were mapped) fails closed as [`ClaimMappingError::MappingInvalid`]. Only a fully
/// valid document is returned, so a mapping failure never provisions a partial
/// identity.
///
/// `schema` is [`None`] when the scope has no active trait schema; a mapping that
/// produces traits then fails closed (a `Config` fault), while a mapping that
/// produces no traits succeeds (a minimal, trait-free identity needs no schema).
///
/// # Errors
///
/// [`ClaimMappingError::UpstreamClaim`] if a required claim is absent or the subject
/// claim is malformed; [`ClaimMappingError::MappingInvalid`] if the assembled traits
/// fail the active schema's type check or the scope has no active schema for the
/// mapped traits.
///
/// # The Apple first-authorization-only reuse (issue #74)
///
/// `prior_traits` is the RETURNING federated user's stored trait document, or [`None`]
/// for a first login. When [`Quirks::profile_delivered_first_auth_only`] is set (Apple),
/// the upstream delivers name and email ONLY on the first authorization; a subsequent
/// login omits them. So for any trait field the upstream did not deliver, a stored value
/// from `prior_traits` is reused (the persisted profile IS the provisioned traits),
/// letting a returning Apple login succeed instead of failing the required-email check.
/// A FIRST login has no `prior_traits`, so a missing required field still fails closed
/// exactly as before: the crux is that the reuse never weakens the first-login contract.
pub fn evaluate(
    mapping: &ClaimMapping,
    quirks: &Quirks,
    sources: ClaimSources<'_>,
    schema: Option<&dyn TraitSchemaView>,
    prior_traits: Option<&Map<String, Value>>,
) -> Result<TraitDocument, ClaimMappingError> {
    let mut missing: Vec<String> = Vec::new();

    // The subject: resolved from the ID token (the verified, mix-up-checked context)
    // per the subject rule, defaulting to `sub`. A missing required subject or a
    // non-string subject is an UPSTREAM fault.
    let subject_rule = mapping.subject.clone().unwrap_or_else(default_subject_rule);
    let subject = match resolve_rule(&subject_rule, &[sources.id_token]) {
        Some(Value::String(value)) => Some(value),
        Some(_) => {
            return Err(ClaimMappingError::UpstreamClaim {
                pointers: vec!["/subject".to_owned()],
                message: "the resolved subject claim is not a string".to_owned(),
            });
        }
        None => {
            if subject_rule.required {
                missing.push("/subject".to_owned());
            }
            None
        }
    };

    // Each trait field: resolve its ordered fallback against the field's source view.
    let mut traits = Map::new();
    for (field, rule) in &mapping.traits {
        let views = views_for_field(field, quirks, &sources);
        if let Some(value) = resolve_rule(rule, &views) {
            // Canonicalize the resolved `email` value with NFKC BEFORE the type check, so the
            // mapped email is normalized regardless of the claim path it came from (a top-level
            // `email` or a nested path like `emails.0`) and the value that is type-checked is
            // byte-identical to the value provisioned. Only the `email` trait is normalized;
            // every other trait is passed through unchanged.
            let value = if field == EMAIL_FIELD {
                normalize_email_value(value)
            } else {
                value
            };
            traits.insert(field.clone(), value);
        } else {
            // Apple first-authorization-only reuse (issue #74): the upstream omitted this field
            // on a returning login. When the quirk is set and the stored profile carries it,
            // reuse the stored value (email re-normalized) so the returning login succeeds with
            // the persisted profile. A first login has no `prior_traits`, so a missing required
            // field still fails closed below.
            let reused = prior_traits
                .filter(|_| quirks.profile_delivered_first_auth_only)
                .and_then(|prior| prior.get(field))
                .filter(|stored| !stored.is_null());
            if let Some(stored) = reused {
                let stored = if field == EMAIL_FIELD {
                    normalize_email_value(stored.clone())
                } else {
                    stored.clone()
                };
                traits.insert(field.clone(), stored);
            } else if rule.required {
                missing.push(pointer_for(field));
            }
        }
    }

    // A missing required claim is an UPSTREAM fault: the IdP omitted a claim the
    // mapping needs. Reported BEFORE the type check (the document is incomplete).
    if !missing.is_empty() {
        return Err(ClaimMappingError::UpstreamClaim {
            pointers: missing,
            message: "a required claim was absent from the upstream response".to_owned(),
        });
    }

    // Type-check the fully assembled traits against the active schema. Only mapped
    // traits need a schema; a trait-free mapping provisions a minimal identity.
    if !traits.is_empty() {
        let Some(schema) = schema else {
            return Err(ClaimMappingError::MappingInvalid {
                pointers: Vec::new(),
                message: "the scope has no active trait schema to validate the mapped traits \
                          against"
                    .to_owned(),
            });
        };
        let document = Value::Object(traits.clone());
        let failures = schema.type_check(&document);
        if !failures.is_empty() {
            return Err(ClaimMappingError::MappingInvalid {
                pointers: failures.iter().map(|f| f.pointer.clone()).collect(),
                message: summarize(&failures),
            });
        }
    }

    // A subject is always required for a federated identity; the resolution above
    // returns None only when the rule was explicitly non-required, in which case fall
    // back to the standard `sub` (which the verified token always carries). This keeps
    // the returned subject total without changing the identity key.
    let subject = subject
        .or_else(|| resolve_string(sources.id_token, "sub"))
        .unwrap_or_default();

    Ok(TraitDocument { subject, traits })
}

/// The ordered source views for a trait field. Every field resolves ID token then
/// `UserInfo` (ID-token precedence), EXCEPT `email`, whose order is governed by the
/// connector's `email_source` quirk (the one place a provider's non-standard email
/// resolution is expressed as DATA, never a code branch).
fn views_for_field<'a>(
    field: &str,
    quirks: &Quirks,
    sources: &ClaimSources<'a>,
) -> Vec<&'a Map<String, Value>> {
    if field != EMAIL_FIELD {
        return default_views(sources);
    }
    match quirks.email_source {
        EmailSource::IdToken => vec![sources.id_token],
        EmailSource::Userinfo => sources.userinfo.into_iter().collect(),
        EmailSource::FallbackOrder => default_views(sources),
    }
}

/// The default source order: the ID token, then `UserInfo` when present.
fn default_views<'a>(sources: &ClaimSources<'a>) -> Vec<&'a Map<String, Value>> {
    let mut views = vec![sources.id_token];
    if let Some(userinfo) = sources.userinfo {
        views.push(userinfo);
    }
    views
}

/// Resolve a rule's ordered claim-path fallback against the ordered source views: the
/// first path that resolves to a non-null value in the first source that carries it
/// wins. A resolved JSON `null` is treated as absent.
fn resolve_rule(rule: &ClaimRule, views: &[&Map<String, Value>]) -> Option<Value> {
    for path in &rule.source {
        for view in views {
            if let Some(value) = resolve_path(view, path) {
                if !value.is_null() {
                    return Some(value.clone());
                }
            }
        }
    }
    None
}

/// Resolve a dotted claim path against a claim object. A segment descends into an
/// object by key or into an array by a numeric index (for example `emails.0`). A
/// segment that hits a scalar, an absent key, or an out-of-range index resolves to
/// [`None`]. Pure and total: no path can panic.
fn resolve_path<'a>(root: &'a Map<String, Value>, path: &str) -> Option<&'a Value> {
    let mut segments = path.split('.');
    let first = segments.next()?;
    let mut current = root.get(first)?;
    for segment in segments {
        current = match current {
            Value::Object(object) => object.get(segment)?,
            Value::Array(array) => {
                let index: usize = segment.parse().ok()?;
                array.get(index)?
            }
            _ => return None,
        };
    }
    Some(current)
}

/// NFKC-normalize a resolved `email` trait value so the mapped email is canonicalized
/// regardless of the claim path it resolved from. NFKC folds the compatibility-confusable
/// class (fullwidth ASCII, ligatures, circled forms) onto ordinary forms, mirroring the
/// email NFKC boundary IronAuth applies elsewhere. Only a string is normalized; a
/// non-string value is passed through unchanged for the trait-schema type check to reject.
fn normalize_email_value(value: Value) -> Value {
    match value {
        Value::String(email) => Value::String(email.nfkc().collect()),
        other => other,
    }
}

/// Resolve a single top-level string claim, or [`None`] when absent or not a string.
fn resolve_string(root: &Map<String, Value>, key: &str) -> Option<String> {
    root.get(key).and_then(Value::as_str).map(str::to_owned)
}

/// The RFC 6901 JSON Pointer for a top-level trait field (escaping `~` and `/`).
fn pointer_for(field: &str) -> String {
    format!("/{}", field.replace('~', "~0").replace('/', "~1"))
}

/// Summarize type-check failures into one bounded, operator-safe message. The store's
/// failure messages never echo a value, so this carries no PII.
fn summarize(failures: &[TraitPointerFailure]) -> String {
    if let Some(first) = failures.first() {
        let more = failures.len().saturating_sub(1);
        if more == 0 {
            first.message.clone()
        } else {
            format!("{} (and {more} more)", first.message)
        }
    } else {
        "the mapped traits failed the active trait schema".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A tiny fake schema view for the evaluator's unit tests, mirroring the shape of
    /// the store's `TraitSchema::validate`: a fixed set of declared fields, each with
    /// a required JSON type; an undeclared field or a wrong type is a failure. Keeps
    /// the connector crate store-free while exercising the type-check seam.
    struct FakeSchema {
        declared: Vec<(&'static str, &'static str)>,
    }

    impl TraitSchemaView for FakeSchema {
        fn type_check(&self, document: &Value) -> Vec<TraitPointerFailure> {
            let mut failures = Vec::new();
            let Value::Object(map) = document else {
                return failures;
            };
            for (field, value) in map {
                match self.declared.iter().find(|(name, _)| name == field) {
                    None => failures.push(TraitPointerFailure {
                        pointer: format!("/{field}"),
                        message: "additional field is not permitted".to_owned(),
                    }),
                    Some((_, ty)) if !type_ok(ty, value) => failures.push(TraitPointerFailure {
                        pointer: format!("/{field}"),
                        message: "value does not match the required type".to_owned(),
                    }),
                    Some(_) => {}
                }
            }
            failures
        }
    }

    fn type_ok(ty: &str, value: &Value) -> bool {
        match ty {
            "string" => value.is_string(),
            "integer" => value.is_i64() || value.is_u64(),
            _ => true,
        }
    }

    fn schema(declared: Vec<(&'static str, &'static str)>) -> FakeSchema {
        FakeSchema { declared }
    }

    fn obj(value: Value) -> Map<String, Value> {
        match value {
            Value::Object(map) => map,
            _ => panic!("expected a JSON object"),
        }
    }

    fn rule(paths: &[&str], required: bool) -> ClaimRule {
        ClaimRule {
            source: paths.iter().map(|p| (*p).to_owned()).collect(),
            required,
        }
    }

    fn mapping(traits: Vec<(&str, ClaimRule)>) -> ClaimMapping {
        ClaimMapping {
            subject: None,
            traits: traits.into_iter().map(|(k, v)| (k.to_owned(), v)).collect(),
        }
    }

    fn sources_of(id_token: &Map<String, Value>) -> ClaimSources<'_> {
        ClaimSources {
            id_token,
            userinfo: None,
        }
    }

    #[test]
    fn a_dotted_path_resolves_into_nested_objects_and_arrays() {
        let id = obj(json!({
            "sub": "u-1",
            "address": { "locality": "Zurich" },
            "emails": ["a@b.test", "c@d.test"]
        }));
        assert_eq!(
            resolve_path(&id, "address.locality"),
            Some(&json!("Zurich"))
        );
        assert_eq!(resolve_path(&id, "emails.0"), Some(&json!("a@b.test")));
        assert_eq!(resolve_path(&id, "emails.9"), None);
        assert_eq!(resolve_path(&id, "address.missing"), None);
        // Descending into a scalar resolves to None, never a panic.
        assert_eq!(resolve_path(&id, "sub.deeper"), None);
    }

    #[test]
    fn ordered_fallback_takes_the_first_resolving_path() {
        let id = obj(json!({ "sub": "u-1", "emails": ["fallback@x.test"] }));
        let schema = schema(vec![("email", "string")]);
        let map = mapping(vec![("email", rule(&["email", "emails.0"], true))]);
        let doc = evaluate(
            &map,
            &Quirks::default(),
            sources_of(&id),
            Some(&schema),
            None,
        )
        .expect("resolves via fallback");
        assert_eq!(doc.traits.get("email"), Some(&json!("fallback@x.test")));
        assert_eq!(doc.subject, "u-1");
    }

    #[test]
    fn a_missing_required_claim_is_an_upstream_fault_with_a_pointer() {
        let id = obj(json!({ "sub": "u-1" }));
        let schema = schema(vec![("email", "string")]);
        let map = mapping(vec![("email", rule(&["email"], true))]);
        let error = evaluate(
            &map,
            &Quirks::default(),
            sources_of(&id),
            Some(&schema),
            None,
        )
        .expect_err("missing required email");
        match error {
            ClaimMappingError::UpstreamClaim { pointers, .. } => {
                assert_eq!(pointers, vec!["/email".to_owned()]);
            }
            other => panic!("expected UpstreamClaim, got {other:?}"),
        }
        // And it folds to the UpstreamProtocol connector error.
        assert!(matches!(
            ConnectorError::from(
                evaluate(
                    &map,
                    &Quirks::default(),
                    sources_of(&id),
                    Some(&schema),
                    None
                )
                .unwrap_err()
            ),
            ConnectorError::UpstreamProtocol(_)
        ));
    }

    #[test]
    fn an_optional_missing_claim_is_simply_omitted() {
        let id = obj(json!({ "sub": "u-1" }));
        let schema = schema(vec![("email", "string"), ("nickname", "string")]);
        let map = mapping(vec![("nickname", rule(&["nickname"], false))]);
        let doc = evaluate(
            &map,
            &Quirks::default(),
            sources_of(&id),
            Some(&schema),
            None,
        )
        .expect("optional omitted");
        assert!(!doc.traits.contains_key("nickname"));
    }

    #[test]
    fn a_wrong_type_is_a_mapping_config_fault() {
        // The upstream sent email as a NUMBER: a well-formed value that fails the trait
        // schema type check is a mapping-definition fault (Config), never a partial doc.
        let id = obj(json!({ "sub": "u-1", "email": 42 }));
        let schema = schema(vec![("email", "string")]);
        let map = mapping(vec![("email", rule(&["email"], true))]);
        let error = evaluate(
            &map,
            &Quirks::default(),
            sources_of(&id),
            Some(&schema),
            None,
        )
        .expect_err("email is a number");
        match error {
            ClaimMappingError::MappingInvalid { pointers, .. } => {
                assert_eq!(pointers, vec!["/email".to_owned()]);
            }
            other => panic!("expected MappingInvalid, got {other:?}"),
        }
        assert!(matches!(
            ConnectorError::from(
                evaluate(
                    &map,
                    &Quirks::default(),
                    sources_of(&id),
                    Some(&schema),
                    None
                )
                .unwrap_err()
            ),
            ConnectorError::Config(_)
        ));
    }

    #[test]
    fn a_rule_targeting_an_undeclared_trait_is_a_config_fault() {
        let id = obj(json!({ "sub": "u-1", "email": "a@b.test" }));
        // The schema does NOT declare `email`, so mapping to it is a definition fault.
        let schema = schema(vec![("name", "string")]);
        let map = mapping(vec![("email", rule(&["email"], true))]);
        let error = evaluate(
            &map,
            &Quirks::default(),
            sources_of(&id),
            Some(&schema),
            None,
        )
        .expect_err("undeclared trait");
        assert!(matches!(error, ClaimMappingError::MappingInvalid { .. }));
    }

    #[test]
    fn mapped_traits_with_no_active_schema_fail_closed_as_config() {
        let id = obj(json!({ "sub": "u-1", "email": "a@b.test" }));
        let map = mapping(vec![("email", rule(&["email"], true))]);
        let error =
            evaluate(&map, &Quirks::default(), sources_of(&id), None, None).expect_err("no schema");
        assert!(matches!(error, ClaimMappingError::MappingInvalid { .. }));
    }

    #[test]
    fn a_traitless_mapping_needs_no_schema_and_carries_the_subject() {
        let id = obj(json!({ "sub": "u-1" }));
        let doc = evaluate(
            &ClaimMapping::default(),
            &Quirks::default(),
            sources_of(&id),
            None,
            None,
        )
        .expect("empty mapping provisions a minimal identity");
        assert!(doc.is_traitless());
        assert_eq!(doc.subject, "u-1");
    }

    #[test]
    fn email_source_userinfo_reads_only_userinfo() {
        let id = obj(json!({ "sub": "u-1", "email": "idtoken@x.test" }));
        let userinfo = obj(json!({ "email": "userinfo@x.test" }));
        let schema = schema(vec![("email", "string")]);
        let map = mapping(vec![("email", rule(&["email"], true))]);
        let quirks = Quirks {
            email_source: EmailSource::Userinfo,
            ..Quirks::default()
        };
        let doc = evaluate(
            &map,
            &quirks,
            ClaimSources {
                id_token: &id,
                userinfo: Some(&userinfo),
            },
            Some(&schema),
            None,
        )
        .expect("resolves from userinfo");
        assert_eq!(doc.traits.get("email"), Some(&json!("userinfo@x.test")));
    }

    #[test]
    fn email_source_fallback_order_prefers_the_id_token() {
        let id = obj(json!({ "sub": "u-1", "email": "idtoken@x.test" }));
        let userinfo = obj(json!({ "email": "userinfo@x.test" }));
        let schema = schema(vec![("email", "string")]);
        let map = mapping(vec![("email", rule(&["email"], true))]);
        let quirks = Quirks {
            email_source: EmailSource::FallbackOrder,
            ..Quirks::default()
        };
        let doc = evaluate(
            &map,
            &quirks,
            ClaimSources {
                id_token: &id,
                userinfo: Some(&userinfo),
            },
            Some(&schema),
            None,
        )
        .expect("resolves");
        assert_eq!(doc.traits.get("email"), Some(&json!("idtoken@x.test")));
    }

    #[test]
    fn email_source_userinfo_without_userinfo_fails_closed() {
        // A connector configured to read email from UserInfo, but no UserInfo was
        // fetched: a required email then resolves to nothing (an upstream fault).
        let id = obj(json!({ "sub": "u-1", "email": "idtoken@x.test" }));
        let schema = schema(vec![("email", "string")]);
        let map = mapping(vec![("email", rule(&["email"], true))]);
        let quirks = Quirks {
            email_source: EmailSource::Userinfo,
            ..Quirks::default()
        };
        let error = evaluate(&map, &quirks, sources_of(&id), Some(&schema), None)
            .expect_err("no userinfo, required email");
        assert!(matches!(error, ClaimMappingError::UpstreamClaim { .. }));
    }

    #[test]
    fn a_custom_subject_rule_resolves_the_subject() {
        let id = obj(json!({ "oid": "provider-oid-9", "sub": "u-1" }));
        let map = ClaimMapping {
            subject: Some(rule(&["oid"], true)),
            traits: std::collections::BTreeMap::new(),
        };
        let doc = evaluate(&map, &Quirks::default(), sources_of(&id), None, None)
            .expect("custom subject");
        assert_eq!(doc.subject, "provider-oid-9");
    }

    #[test]
    fn a_mapped_email_is_nfkc_normalized_from_any_path() {
        // The email resolves from a NON-top-level path (`emails.0`), and the value carries a
        // compatibility-confusable (the fullwidth commercial-at U+FF20). It must be NFKC-folded
        // to the ordinary ASCII form the schema type-checks and the identity is provisioned with.
        let id = obj(json!({ "sub": "u-1", "emails": ["user\u{FF20}x.test"] }));
        let schema = schema(vec![("email", "string")]);
        let map = mapping(vec![("email", rule(&["emails.0"], true))]);
        let doc = evaluate(
            &map,
            &Quirks::default(),
            sources_of(&id),
            Some(&schema),
            None,
        )
        .expect("resolves and normalizes");
        assert_eq!(doc.traits.get("email"), Some(&json!("user@x.test")));
    }

    #[test]
    fn a_non_string_subject_is_an_upstream_fault() {
        let id = obj(json!({ "sub": 12345 }));
        let error = evaluate(
            &ClaimMapping::default(),
            &Quirks::default(),
            sources_of(&id),
            None,
            None,
        )
        .expect_err("numeric subject");
        assert!(matches!(error, ClaimMappingError::UpstreamClaim { .. }));
    }
}
