// SPDX-License-Identifier: MIT OR Apache-2.0

//! The typed, versioned event catalog (issue #108).
//!
//! # The registry is DERIVED, not hand written
//!
//! Every event type comes from [`crate::audit::Action`]'s own `as_str` body, scanned out of
//! this crate's source exactly as the uniqueness test in `audit.rs` does. That note says why
//! the scan and not a list: `Action` has no `ALL` to iterate, so a hand-maintained catalog
//! would drift from the actions the code actually emits, and the drift is invisible because
//! nothing compares them. Deriving both from one source makes the comparison automatic.
//!
//! # What a registered event promises
//!
//! Every type carries a PAYLOAD SCHEMA VERSION and a JSON Schema. Two of those schemas are
//! real contracts today and the rest are explicit placeholders, which is a distinction this
//! module refuses to blur:
//!
//! * A SPECIFIED payload has a schema naming its fields. A consumer can code against it.
//! * An UNSPECIFIED payload has `{"type": "object"}` and says so in
//!   [`RegisteredEvent::payload_specified`]. It is not a contract, it is an admission, and
//!   [`UNSPECIFIED_CEILING`] ratchets the count down so the admission cannot grow.
//!
//! Writing 232 invented schemas to make a criterion read as satisfied would be worse than
//! either: a consumer would code against a contract nobody had thought about, and the first
//! real payload would break it.
//!
//! # Versioning
//!
//! Additive changes extend a version; a breaking change mints a new one. The committed
//! artifact (`docs/events/catalog.json`) is what makes that enforceable: a schema edited
//! under an unchanged version shows up as a diff in a file a reviewer reads, and the
//! freshness gate refuses the commit until somebody looks.

use serde_json::{Value, json};

use crate::trait_schema::TraitSchema;

/// The audit source the event types are scanned out of.
const AUDIT_SOURCE: &str = include_str!("audit.rs");

/// The envelope every event carries, on the push path and the pull path alike (issue #108).
///
/// A consumer validates THIS before it looks at the payload, so a malformed envelope is a
/// transport problem it can report rather than a payload problem it cannot parse.
#[must_use]
pub fn envelope_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "id": {"type": "string", "minLength": 1},
            "type": {"type": "string", "minLength": 1},
            "payload_schema_version": {"type": "integer"},
            "occurred_at_unix_ms": {"type": "integer"},
            "tenant_id": {"type": "string", "minLength": 1},
            "environment_id": {"type": "string", "minLength": 1},
            "payload": {"type": "object"}
        },
        "required": [
            "id",
            "type",
            "payload_schema_version",
            "occurred_at_unix_ms",
            "tenant_id",
            "environment_id",
            "payload"
        ]
    })
}

/// The payload schemas that are REAL contracts, as `(event type, version, schema)`.
///
/// Adding one here is what moves a type from admitted-unspecified to specified, and the
/// ceiling below must come down in the same change.
const SPECIFIED_PAYLOADS: &[(&str, u32, &str)] = &[
    (
        "user.create",
        1,
        r#"{
            "type": "object",
            "properties": {
                "user_id": {"type": "string", "minLength": 1},
                "state": {"type": "string", "minLength": 1}
            },
            "required": ["user_id", "state"]
        }"#,
    ),
    (
        "user.delete",
        1,
        r#"{
            "type": "object",
            "properties": {
                "user_id": {"type": "string", "minLength": 1}
            },
            "required": ["user_id"]
        }"#,
    ),
];

/// How many registered types may still lack a real payload contract.
///
/// A RATCHET, the shape `scripts/provider-coverage.sh` and `test-registration.sh` use: it may
/// only come down. Demanding all 232 today would be a gate somebody disables; letting the
/// number drift up would make the admission meaningless.
pub const UNSPECIFIED_CEILING: usize = 230;

/// The floor on registered types, so a scan that silently read nothing cannot pass.
///
/// Issue #108 asks for at least 100. The scan finds 232 today; the floor is the criterion's
/// number rather than today's, so ordinary churn does not trip it but a broken scan does.
pub const MINIMUM_REGISTERED_TYPES: usize = 100;

/// One registered event type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredEvent {
    /// The wire type, for example `user.create`.
    pub wire: String,
    /// The leading segment, for example `user`. The catalog groups by it.
    pub domain: String,
    /// The payload schema version this type currently emits.
    pub payload_version: u32,
    /// The payload JSON Schema, as text.
    pub payload_schema: String,
    /// Whether the schema is a real contract or the explicit placeholder.
    pub payload_specified: bool,
}

/// Every event type the code can emit, scanned from [`crate::audit::Action`].
///
/// # Panics
///
/// If the scan cannot find the `as_str` body, which means the function was renamed or
/// reflowed. Panicking is right: a catalog built from a scan that read nothing would be an
/// empty catalog that passed every count it was not given a floor for.
#[must_use]
pub fn event_types() -> Vec<String> {
    // Assembled from fragments so this scanner never matches its own source line, the same
    // guard the uniqueness test in `audit.rs` uses and for the same reason.
    let needle = concat!("pub fn ", "as_str(&self) -> &'static str {");
    let body = AUDIT_SOURCE
        .split_once(needle)
        .map(|(_, rest)| rest)
        .expect("the as_str body is readable");
    let body = body
        .split_once("\n    }\n")
        .map(|(inside, _)| inside)
        .expect("the as_str body is terminated");

    let mut out = Vec::new();
    let mut rest = body;
    while let Some(start) = rest.find('"') {
        rest = &rest[start + 1..];
        let Some(end) = rest.find('"') else { break };
        let literal = &rest[..end];
        rest = &rest[end + 1..];
        if !literal.is_empty() {
            out.push(literal.to_owned());
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// The full registry: every scanned type with its schema.
#[must_use]
pub fn registry() -> Vec<RegisteredEvent> {
    event_types()
        .into_iter()
        .map(|wire| {
            let domain = wire
                .split_once('.')
                .map_or_else(|| wire.clone(), |(head, _)| head.to_owned());
            match SPECIFIED_PAYLOADS.iter().find(|(name, _, _)| *name == wire) {
                Some((_, version, schema)) => RegisteredEvent {
                    wire,
                    domain,
                    payload_version: *version,
                    payload_schema: (*schema).to_owned(),
                    payload_specified: true,
                },
                None => RegisteredEvent {
                    wire,
                    domain,
                    payload_version: 1,
                    // Explicitly permissive, and flagged. See the module note.
                    payload_schema: r#"{"type": "object"}"#.to_owned(),
                    payload_specified: false,
                },
            }
        })
        .collect()
}

/// Look one type up.
#[must_use]
pub fn registered(wire: &str) -> Option<RegisteredEvent> {
    registry().into_iter().find(|entry| entry.wire == wire)
}

/// Why an envelope was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogError {
    /// The envelope itself is malformed; the strings are JSON Pointer failures.
    Envelope(Vec<String>),
    /// The `type` names a type the registry does not carry. This is the check that makes
    /// "emitting an unregistered type fails the build" enforceable.
    UnregisteredType(String),
    /// The payload does not satisfy the registered schema for its type.
    Payload {
        /// The event type.
        wire: String,
        /// The JSON Pointer failures.
        failures: Vec<String>,
    },
    /// The envelope declares a payload version the registry does not emit.
    VersionMismatch {
        /// The event type.
        wire: String,
        /// What the envelope declared.
        declared: u32,
        /// What the registry says.
        registered: u32,
    },
}

/// Validate one envelope against the catalog: shape, then registration, then payload.
///
/// The order matters. A malformed envelope has no trustworthy `type`, so checking
/// registration first would report "unregistered type" for what is really a broken producer.
///
/// # Errors
///
/// [`CatalogError`] describing the first check that failed.
///
/// # Panics
///
/// If the envelope schema or a registered payload schema fails to compile. Both are
/// compile-time constants in this module and `every_registered_schema_compiles` pins them,
/// so reaching either panic means that test was deleted.
pub fn validate_event(envelope: &Value) -> Result<(), CatalogError> {
    let schema = TraitSchema::compile(&envelope_schema().to_string())
        .expect("the envelope schema is a compile-time constant and compiles");
    let failures = schema.validate(envelope);
    if !failures.is_empty() {
        return Err(CatalogError::Envelope(
            failures
                .iter()
                .map(|failure| format!("{}: {}", failure.pointer, failure.message))
                .collect(),
        ));
    }
    let wire = envelope
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let Some(entry) = registered(&wire) else {
        return Err(CatalogError::UnregisteredType(wire));
    };
    let declared = envelope
        .get("payload_schema_version")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let declared = u32::try_from(declared).unwrap_or(u32::MAX);
    if declared != entry.payload_version {
        return Err(CatalogError::VersionMismatch {
            wire,
            declared,
            registered: entry.payload_version,
        });
    }
    let payload = envelope.get("payload").cloned().unwrap_or(json!({}));
    let payload_schema = TraitSchema::compile(&entry.payload_schema)
        .expect("a registered payload schema compiles; a test pins that");
    let failures = payload_schema.validate(&payload);
    if !failures.is_empty() {
        return Err(CatalogError::Payload {
            wire,
            failures: failures
                .iter()
                .map(|failure| format!("{}: {}", failure.pointer, failure.message))
                .collect(),
        });
    }
    Ok(())
}

/// The catalog as the committed artifact, for the docs generator and the freshness gate.
#[must_use]
pub fn catalog_document() -> Value {
    let entries: Vec<Value> = registry()
        .into_iter()
        .map(|entry| {
            json!({
                "type": entry.wire,
                "domain": entry.domain,
                "payload_schema_version": entry.payload_version,
                "payload_specified": entry.payload_specified,
                "payload_schema": serde_json::from_str::<Value>(&entry.payload_schema)
                    .unwrap_or(json!({})),
            })
        })
        .collect();
    json!({
        "envelope_schema": envelope_schema(),
        "event_types": entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The scan finds a plausible number of types, well past the criterion's floor.
    ///
    /// The floor is what stops a scan that silently read NOTHING from passing: an empty
    /// registry satisfies "every registered schema compiles" and "no duplicates" perfectly.
    #[test]
    fn the_scan_finds_at_least_the_floor_and_the_types_are_distinct() {
        let types = event_types();
        assert!(
            types.len() >= MINIMUM_REGISTERED_TYPES,
            "the scan found {} event types, below the floor of {MINIMUM_REGISTERED_TYPES}; \
             a scan that read nothing would otherwise pass every other test here",
            types.len()
        );
        let mut sorted = types.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            types.len(),
            "two event types share a wire string"
        );
    }

    /// The registry covers EVERY scanned type, with no extras.
    ///
    /// Both directions. A missing type is an event nothing can validate; an extra one is a
    /// catalog entry for something the code cannot emit, which a consumer would wait for
    /// forever.
    #[test]
    fn the_registry_covers_exactly_the_scanned_types() {
        let scanned = event_types();
        let registered: Vec<String> = registry().into_iter().map(|entry| entry.wire).collect();
        assert_eq!(registered, scanned);
    }

    /// Every registered payload schema COMPILES, and so does the envelope schema.
    ///
    /// `validate_event` expects both, and an uncompilable schema would turn every event of
    /// that type into a panic on the delivery path.
    #[test]
    fn every_registered_schema_compiles() {
        TraitSchema::compile(&envelope_schema().to_string()).expect("the envelope schema compiles");
        for entry in registry() {
            TraitSchema::compile(&entry.payload_schema).unwrap_or_else(|error| {
                panic!(
                    "the schema for `{}` does not compile: {error:?}",
                    entry.wire
                )
            });
        }
    }

    /// The unspecified count is at or under the ceiling, and the ceiling ratchets.
    #[test]
    fn the_unspecified_payload_count_is_within_the_ratchet() {
        let unspecified = registry()
            .into_iter()
            .filter(|entry| !entry.payload_specified)
            .count();
        assert!(
            unspecified <= UNSPECIFIED_CEILING,
            "{unspecified} event types lack a payload contract, above the ceiling of \
             {UNSPECIFIED_CEILING}: a new event type landed without one"
        );
        assert!(
            unspecified >= UNSPECIFIED_CEILING,
            "only {unspecified} types are unspecified, below the ceiling of \
             {UNSPECIFIED_CEILING}. Lower UNSPECIFIED_CEILING to {unspecified} so the gain \
             is locked in; a ratchet that is never tightened is a ceiling nobody notices"
        );
    }

    /// Every SPECIFIED payload names a type the registry actually carries.
    ///
    /// A schema for a type that does not exist is a contract nothing can ever satisfy, and
    /// it silently costs the ratchet a slot.
    #[test]
    fn every_specified_payload_names_a_real_event_type() {
        let scanned = event_types();
        for (wire, _, _) in SPECIFIED_PAYLOADS {
            assert!(
                scanned.iter().any(|found| found == wire),
                "`{wire}` has a payload schema but is not an event type the code emits"
            );
        }
    }

    fn good_envelope() -> Value {
        json!({
            "id": "evt_1",
            "type": "user.create",
            "payload_schema_version": 1,
            "occurred_at_unix_ms": 1_700_000_000_000_i64,
            "tenant_id": "ten_1",
            "environment_id": "env_1",
            "payload": {"user_id": "usr_1", "state": "active"}
        })
    }

    /// A well-formed event validates.
    #[test]
    fn a_well_formed_event_validates() {
        assert_eq!(validate_event(&good_envelope()), Ok(()));
    }

    /// EVERY required envelope field is required, one at a time.
    ///
    /// Asserted per field rather than once, because a schema that required only `id` would
    /// pass a single happy-path test and let every other field go missing.
    #[test]
    fn removing_any_required_envelope_field_is_refused() {
        for field in [
            "id",
            "type",
            "payload_schema_version",
            "occurred_at_unix_ms",
            "tenant_id",
            "environment_id",
            "payload",
        ] {
            let mut envelope = good_envelope();
            envelope
                .as_object_mut()
                .expect("an object")
                .remove(field)
                .expect("the field was present");
            assert!(
                matches!(validate_event(&envelope), Err(CatalogError::Envelope(_))),
                "an envelope missing `{field}` was accepted"
            );
        }
    }

    /// An UNREGISTERED type is refused by name. This is the check that makes "emitting an
    /// unregistered event fails the build" enforceable.
    #[test]
    fn an_unregistered_event_type_is_refused() {
        let mut envelope = good_envelope();
        envelope["type"] = json!("user.invented_by_nobody");
        assert_eq!(
            validate_event(&envelope),
            Err(CatalogError::UnregisteredType(
                "user.invented_by_nobody".to_owned()
            ))
        );
    }

    /// A payload that violates its registered schema is refused, and the error names the
    /// type so an operator knows which producer to look at.
    #[test]
    fn a_payload_violating_its_registered_schema_is_refused() {
        let mut envelope = good_envelope();
        envelope["payload"] = json!({"user_id": "usr_1"});
        match validate_event(&envelope) {
            Err(CatalogError::Payload { wire, failures }) => {
                assert_eq!(wire, "user.create");
                assert!(!failures.is_empty(), "the refusal must say what failed");
            }
            other => panic!("expected a payload refusal, got {other:?}"),
        }
    }

    /// A version the registry does not emit is refused rather than validated against
    /// whatever schema happens to be current.
    ///
    /// This is the versioning policy's enforcement point: a consumer pinning version 1 must
    /// not silently receive version 2's shape.
    #[test]
    fn a_declared_version_the_registry_does_not_emit_is_refused() {
        let mut envelope = good_envelope();
        envelope["payload_schema_version"] = json!(2);
        assert_eq!(
            validate_event(&envelope),
            Err(CatalogError::VersionMismatch {
                wire: "user.create".to_owned(),
                declared: 2,
                registered: 1,
            })
        );
    }

    /// An UNSPECIFIED type accepts any object payload, and still refuses a non-object.
    ///
    /// The placeholder is permissive on purpose, but it is a schema rather than an absence:
    /// a payload that is not an object at all is still wrong.
    #[test]
    fn an_unspecified_type_accepts_an_object_and_refuses_a_non_object() {
        let unspecified = registry()
            .into_iter()
            .find(|entry| !entry.payload_specified)
            .expect("at least one type is unspecified today");
        let mut envelope = good_envelope();
        envelope["type"] = json!(unspecified.wire);
        envelope["payload"] = json!({"anything": true});
        assert_eq!(validate_event(&envelope), Ok(()));

        envelope["payload"] = json!("not an object");
        assert!(
            validate_event(&envelope).is_err(),
            "the placeholder still requires an object payload"
        );
    }

    /// The catalog document carries every type and the envelope schema.
    #[test]
    fn the_catalog_document_carries_every_type_and_the_envelope() {
        let document = catalog_document();
        assert!(document.get("envelope_schema").is_some());
        let entries = document["event_types"].as_array().expect("an array");
        assert_eq!(entries.len(), registry().len());
        assert!(entries.iter().all(|entry| entry.get("type").is_some()));
    }
}
