// SPDX-License-Identifier: MIT OR Apache-2.0

//! The typed, versioned event catalog (issue #108).
//!
//! # The catalog is the EVENT vocabulary, which is not the audit vocabulary
//!
//! The first version of this module derived the registry from `Action::as_str`, the audit
//! action list, and that was WRONG in a way only the delivery path could show: the audit
//! action is `user.create` and the event on the wire is `user.created`. Wiring catalog
//! validation into the webhook fan-out turned every real delivery red, which is how the
//! mistake surfaced.
//!
//! They are different vocabularies on purpose, and the distinction is the same one
//! [`crate::identity_fact`] draws. An audit action records what an ACTOR DID
//! (`operator X created a user`). An event records what BECAME TRUE (`a user now exists`).
//! A consumer wants the second, and deriving one from the other means inventing a mapping
//! nobody validated.
//!
//! So the registry is the list of types PRODUCERS actually emit, declared here beside their
//! schemas. That makes the count small and honest rather than large and fictional: issue
//! #108 asks for 100+ types, and reaching it means writing ~100 producers, not renaming an
//! audit list.
//!
//! # What a registered event promises
//!
//! Every type carries a payload schema version and a JSON Schema naming its fields. There
//! are no placeholders here: a type is in this registry because something emits it, and
//! anything that emits an event knows what it puts in the payload.
//!
//! # Versioning
//!
//! Additive changes extend a version; a breaking change mints a new one. The committed
//! artifact (`docs/events/catalog.json`) is what makes that enforceable: a schema edited
//! under an unchanged version shows up as a diff in a file a reviewer reads, and the
//! freshness gate refuses the commit until somebody looks.

use serde_json::{Value, json};

use crate::trait_schema::TraitSchema;

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

/// Every event type a producer emits, with its payload contract.
///
/// `(wire type, payload version, payload JSON Schema)`.
///
/// Every entry here has a PRODUCER. A registry entry for an event no producer sends is a
/// contract a consumer would wait on forever, which is the same fiction as an invented
/// payload schema, so nothing is listed until something emits it.
///
/// `user.deleted` and `user.updated` were both in that state -- subscription filter strings
/// in the webhook surface that nothing emitted, so an operator could subscribe and wait
/// forever. They are here now because the management delete and the management PATCH emit
/// them, not because the filter strings existed.
///
/// Adding a producer means adding a row here in the same change. The fan-out validates every
/// envelope against this registry and REFUSES an unregistered type permanently, so a new
/// event cannot reach the wire uncatalogued: the enforcement is the delivery path itself.
const REGISTERED: &[(&str, u32, &str)] = &[
    (
        "user.created",
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
        // Carries the FIRST ENVIRONMENT alongside the tenant, because creating a tenant
        // creates one in the same transaction and the management API returns both
        // (`TenantCreated`). A receiver told only the tenant id would have to go and ask
        // which environment to talk to, and the answer already exists here.
        "tenant.created",
        1,
        r#"{
            "type": "object",
            "properties": {
                "tenant_id": {"type": "string", "minLength": 1},
                "environment_id": {"type": "string", "minLength": 1},
                "display_name": {"type": "string", "minLength": 1}
            },
            "required": ["tenant_id", "environment_id", "display_name"]
        }"#,
    ),
    (
        // A signup form governs what a self-service REGISTRATION collects and requires, so
        // removing one changes who can sign up and with what. The client id rides along
        // because a signup form is per-client and that is how an operator refers to it.
        "signup_form.deleted",
        1,
        r#"{
            "type": "object",
            "properties": {
                "signup_form_id": {"type": "string", "minLength": 1},
                "client_id": {"type": "string", "minLength": 1}
            },
            "required": ["signup_form_id", "client_id"]
        }"#,
    ),
    (
        // The DEPROVISIONING event. A state that ends sessions kills every live one in the
        // same transaction, so downstream systems act on this one: it is the notice that an
        // account stopped being able to log in.
        //
        // `state` is the destination only. The FROM state is deliberately absent: this write
        // re-checks `state = from` inside the transaction, so an event carrying a transition
        // would be asserting a pair the receiver cannot verify and does not need -- what it
        // acts on is where the account ended up.
        //
        // `hard_kill` rides along because it changes what the change DID: it decides whether
        // offline refresh families were revoked too, and a receiver cannot infer that later.
        "user.state_changed",
        1,
        r#"{
            "type": "object",
            "properties": {
                "user_id": {"type": "string", "minLength": 1},
                "state": {"type": "string", "minLength": 1},
                "hard_kill": {"type": "boolean"}
            },
            "required": ["user_id", "state", "hard_kill"]
        }"#,
    ),
    (
        // Emitted at most ONCE per credential. The revocation is idempotent -- a retried
        // revoke changes nothing and audits nothing -- and the event inherits that, so a
        // receiver counting revocations never sees two for one key because a client retried.
        //
        // The id only, for the reason on `management_key.revoked`: nothing derived from the
        // secret belongs on the wire that announces it is dead.
        "api_key.revoked",
        1,
        r#"{
            "type": "object",
            "properties": {
                "api_key_id": {"type": "string", "minLength": 1}
            },
            "required": ["api_key_id"]
        }"#,
    ),
    (
        // REVOKED, not "deleted", because that is what happened: a management credential lost
        // its authority. The row survives as a tombstone, and a receiver that treated this as
        // a row deletion would garbage-collect audit references that must stay legible.
        //
        // No key material and no prefix: the id is enough to correlate, and anything derived
        // from the secret would put a fragment of a credential on a wire this event exists to
        // tell people to stop trusting.
        "management_key.revoked",
        1,
        r#"{
            "type": "object",
            "properties": {
                "management_key_id": {"type": "string", "minLength": 1}
            },
            "required": ["management_key_id"]
        }"#,
    ),
    (
        // Removing a connector changes WHO CAN LOG IN to this environment, which is why a
        // receiver wants it promptly rather than at the next reconcile. The SLUG rides along
        // with the id because that is what a connector is referenced by everywhere else --
        // in routing rules, in the federation URL, in an operator's own configuration -- so
        // an id alone would send the receiver looking it up in a row that no longer exists.
        "connector.deleted",
        1,
        r#"{
            "type": "object",
            "properties": {
                "connector_id": {"type": "string", "minLength": 1},
                "slug": {"type": "string", "minLength": 1}
            },
            "required": ["connector_id", "slug"]
        }"#,
    ),
    (
        // Deleting an environment FENCES its data plane: the same transaction flips
        // environment_states to suspended. So this event means "this environment stopped
        // serving", which is the fact a receiver acts on -- it is not merely a row change,
        // and every client of that environment is affected at once.
        "environment.deleted",
        1,
        r#"{
            "type": "object",
            "properties": {
                "environment_id": {"type": "string", "minLength": 1},
                "tenant_id": {"type": "string", "minLength": 1}
            },
            "required": ["environment_id", "tenant_id"]
        }"#,
    ),
    (
        // A HARD delete, unlike the user and organization tombstones, so a receiver cannot
        // read the row back to confirm. That makes the event the only notice it gets, which
        // is why the payload carries the client_id and nothing that could go stale.
        "client.deleted",
        1,
        r#"{
            "type": "object",
            "properties": {
                "client_id": {"type": "string", "minLength": 1}
            },
            "required": ["client_id"]
        }"#,
    ),
    (
        // The display name is carried because it is the whole of what a create decided that a
        // receiver cannot derive from the id. Everything else about a new organization is
        // either the id itself or scope, both already on the envelope.
        "organization.created",
        1,
        r#"{
            "type": "object",
            "properties": {
                "organization_id": {"type": "string", "minLength": 1},
                "display_name": {"type": "string", "minLength": 1}
            },
            "required": ["organization_id", "display_name"]
        }"#,
    ),
    (
        // No display name here: the delete is a soft tombstone and the receiver has had the
        // name since the create. Repeating it would invite a consumer to treat the delete as
        // the authoritative record of a name it may have since changed.
        "organization.deleted",
        1,
        r#"{
            "type": "object",
            "properties": {
                "organization_id": {"type": "string", "minLength": 1}
            },
            "required": ["organization_id"]
        }"#,
    ),
    (
        // `fields` names WHAT changed, because a PATCH may carry claims, traits, or both, and
        // a receiver that has to re-read the whole user to find out has gained nothing from
        // being told. It is a list rather than a single value for the same reason.
        //
        // One event per WRITE, not per request. The management PATCH runs claims and traits
        // as two separate audited transactions on purpose (they are different facts and an
        // operator reads them separately), and an event has to be transactional with the
        // write it announces -- so a combined patch emits two, each naming its own field. The
        // alternative, one event after both, cannot be transactional with either: if the
        // traits write failed after the claims write committed, no event would be emitted at
        // all and a real change would be silent.
        "user.updated",
        1,
        r#"{
            "type": "object",
            "properties": {
                "user_id": {"type": "string", "minLength": 1},
                "fields": {
                    "type": "array",
                    "minItems": 1,
                    "items": {"type": "string", "enum": ["claims", "traits"]}
                }
            },
            "required": ["user_id", "fields"]
        }"#,
    ),
    (
        // `hard_kill` rides the payload because it changes what the delete DID, not just
        // that it happened: a soft delete leaves the offline refresh families alive and a
        // hard kill revokes them. A receiver reconciling its own copy needs to tell those
        // apart, and it cannot ask afterwards -- the user reads as absent either way.
        "user.deleted",
        1,
        r#"{
            "type": "object",
            "properties": {
                "user_id": {"type": "string", "minLength": 1},
                "hard_kill": {"type": "boolean"}
            },
            "required": ["user_id", "hard_kill"]
        }"#,
    ),
];

/// Build the envelope a receiver is sent, stamping the version the REGISTRY declares for
/// `event_type`.
///
/// The version is looked up rather than passed, and that is the point of building it here:
/// the envelope and the schema it must validate against are now produced from one source, so
/// a producer cannot stamp a version the registry does not have. A hand-passed version is a
/// second declaration of the same fact, and the fan-out refuses a mismatch permanently --
/// which surfaces as an undeliverable event rather than a compile error.
///
/// Returns `None` for an unregistered type. That is not a convenience: a producer for a type
/// the registry does not know is exactly what the fan-out refuses, and failing here means the
/// write that would have announced it never happens.
#[must_use]
pub fn envelope(
    id: &str,
    event_type: &str,
    tenant_id: &str,
    environment_id: &str,
    occurred_at_unix_ms: i64,
    payload: &serde_json::Value,
) -> Option<serde_json::Value> {
    let version = registered(event_type)?.payload_version;
    Some(serde_json::json!({
        "id": id,
        "type": event_type,
        "payload_schema_version": version,
        "occurred_at_unix_ms": occurred_at_unix_ms,
        "tenant_id": tenant_id,
        "environment_id": environment_id,
        "payload": payload,
    }))
}

/// The number of event types issue #108 asks the catalog to reach before it closes.
///
/// Stated as a constant the tests read so the gap is a NUMBER somebody can see rather than a
/// sentence in an issue. Reaching it means writing producers; see the module note on why it
/// cannot be reached by renaming the audit list.
pub const TARGET_REGISTERED_TYPES: usize = 100;

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
}

/// Every registered event type, sorted.
#[must_use]
pub fn event_types() -> Vec<String> {
    let mut out: Vec<String> = REGISTERED
        .iter()
        .map(|(wire, _, _)| (*wire).to_owned())
        .collect();
    out.sort_unstable();
    out
}

/// The full registry.
#[must_use]
pub fn registry() -> Vec<RegisteredEvent> {
    let mut out: Vec<RegisteredEvent> = REGISTERED
        .iter()
        .map(|(wire, version, schema)| RegisteredEvent {
            wire: (*wire).to_owned(),
            domain: wire
                .split_once('.')
                .map_or_else(|| (*wire).to_owned(), |(head, _)| head.to_owned()),
            payload_version: *version,
            payload_schema: (*schema).to_owned(),
        })
        .collect();
    out.sort_by(|a, b| a.wire.cmp(&b.wire));
    out
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

    /// The registry is non-empty, its types are distinct, and the distance to issue #108's
    /// target is stated rather than implied.
    ///
    /// The gap is an assertion so it cannot be forgotten: 100+ types is reached by writing
    /// PRODUCERS, and this fails loudly the day somebody believes it was reached by
    /// renaming something.
    #[test]
    fn the_registry_is_non_empty_distinct_and_reports_its_distance_to_the_target() {
        let types = event_types();
        assert!(!types.is_empty(), "the registry is empty");
        let mut sorted = types.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            types.len(),
            "two event types share a wire string"
        );
        assert!(
            types.len() < TARGET_REGISTERED_TYPES,
            "the registry reached {} types, at or past issue #108's target of \
             {TARGET_REGISTERED_TYPES}. Raise or retire TARGET_REGISTERED_TYPES and say so \
             in the issue: the target is a reminder that the catalog is incomplete, and a \
             reminder nobody updates is a reminder that lies.",
            types.len()
        );
    }

    /// Every registered type is a dotted, `snake_case` token in the PAST TENSE.
    ///
    /// The past tense is the vocabulary rule that keeps this list from drifting back into
    /// the audit vocabulary, which is imperative (`user.create`). Asserted rather than
    /// documented, because that drift is the defect this module was born from.
    #[test]
    fn every_registered_type_is_a_dotted_past_tense_token() {
        for wire in event_types() {
            let (domain, rest) = wire
                .split_once('.')
                .unwrap_or_else(|| panic!("`{wire}` is not a dotted token"));
            assert!(
                !domain.is_empty() && !rest.is_empty(),
                "`{wire}` has an empty segment"
            );
            assert!(
                wire.chars()
                    .all(|c| c.is_ascii_lowercase() || c == '.' || c == '_'),
                "`{wire}` is not a snake_case dotted token"
            );
            assert!(
                rest.ends_with("ed"),
                "`{wire}` is not past tense. An event records what BECAME TRUE; the \
                 imperative form is the AUDIT vocabulary, and conflating the two is the \
                 defect this rule exists to prevent."
            );
        }
    }

    /// Every registered payload schema COMPILES, and so does the envelope schema.
    ///
    /// `validate_event` expects both, and an uncompilable schema would turn every event of
    /// that type into a panic on the delivery path.
    #[test]
    fn every_registered_schema_compiles() {
        TraitSchema::compile(&envelope_schema().to_string()).expect("the envelope compiles");
        for entry in registry() {
            TraitSchema::compile(&entry.payload_schema).unwrap_or_else(|error| {
                panic!(
                    "the schema for `{}` does not compile: {error:?}",
                    entry.wire
                )
            });
        }
    }

    fn good_envelope() -> Value {
        json!({
            "id": "evt_1",
            "type": "user.created",
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
    /// Asserted per field rather than once, because a schema requiring only `id` would pass
    /// a single happy-path test while every other field went missing.
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

    /// An UNREGISTERED type is refused by name, which is what makes "emitting an
    /// unregistered event fails" enforceable at the delivery choke point.
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

    /// An AUDIT action string is not an event type, and is refused as unregistered.
    ///
    /// The specific confusion that produced the first version of this module, pinned so it
    /// cannot come back quietly.
    #[test]
    fn an_audit_action_string_is_not_an_event_type() {
        let mut envelope = good_envelope();
        envelope["type"] = json!("user.create");
        assert!(
            matches!(
                validate_event(&envelope),
                Err(CatalogError::UnregisteredType(_))
            ),
            "`user.create` is the AUDIT vocabulary; the event is `user.created`"
        );
    }

    /// A payload that violates its registered schema is refused, naming the type.
    #[test]
    fn a_payload_violating_its_registered_schema_is_refused() {
        let mut envelope = good_envelope();
        envelope["payload"] = json!({"user_id": "usr_1"});
        match validate_event(&envelope) {
            Err(CatalogError::Payload { wire, failures }) => {
                assert_eq!(wire, "user.created");
                assert!(!failures.is_empty(), "the refusal must say what failed");
            }
            other => panic!("expected a payload refusal, got {other:?}"),
        }
    }

    /// A version the registry does not emit is refused rather than validated against
    /// whatever schema is current: the versioning policy's enforcement point.
    #[test]
    fn a_declared_version_the_registry_does_not_emit_is_refused() {
        let mut envelope = good_envelope();
        envelope["payload_schema_version"] = json!(2);
        assert_eq!(
            validate_event(&envelope),
            Err(CatalogError::VersionMismatch {
                wire: "user.created".to_owned(),
                declared: 2,
                registered: 1,
            })
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
