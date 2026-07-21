// SPDX-License-Identifier: MIT OR Apache-2.0

//! The published flow contract artifacts (issue #84): the JSON Schema for the flow object
//! and the numeric message id registry snapshot. Both derive from the code itself (the
//! `Flow` types and the message [`REGISTRY`]), so the committed `docs/flow-schema.json` and
//! `docs/flow-messages.json` can never drift; the `scripts/flow-schema.sh` CI gate diffs
//! them exactly like the connector schema gate.

use schemars::schema_for;
use serde_json::{Value, json};

use super::message::{MessageKind, REGISTRY};
use super::model::{CONTRACT_VERSION, Flow};

/// The JSON Schema for the flow object (issue #84), generated from the [`Flow`] type. This
/// is the NORMATIVE wire contract every M9 surface and every M12 SDK binds to.
///
/// # Panics
///
/// Panics only if the derived schema fails to serialize to JSON, which is a compile time
/// impossibility for these types (a build breaking programming error, never a runtime one).
#[must_use]
pub fn flow_object_schema() -> Value {
    serde_json::to_value(schema_for!(Flow)).expect("the flow schema serializes")
}

/// The wire string for a message kind (matching the serde `snake_case` rename).
fn kind_str(kind: MessageKind) -> &'static str {
    match kind {
        MessageKind::Info => "info",
        MessageKind::Success => "success",
        MessageKind::Error => "error",
    }
}

/// The message id registry snapshot (issue #84): every registered id with its symbolic
/// name, kind, default `en` text, and context keys, plus the contract version. This is the
/// committed `docs/flow-messages.json`; a CI diff gate fails a build that changes or
/// removes an id (new ids are additive), which is the "a snapshot test locks the id
/// assignments" acceptance criterion. i18n (issue #86) keys on these ids.
#[must_use]
pub fn flow_messages_snapshot() -> Value {
    let messages: Vec<Value> = REGISTRY
        .iter()
        .map(|spec| {
            json!({
                "id": spec.id.0,
                "name": spec.name,
                "kind": kind_str(spec.kind),
                "text": spec.text,
                "context_keys": spec.context_keys,
            })
        })
        .collect();
    json!({
        "contract_version": CONTRACT_VERSION,
        "messages": messages,
    })
}

#[cfg(test)]
mod tests {
    use super::{flow_messages_snapshot, flow_object_schema};

    #[test]
    fn the_flow_schema_is_a_nonempty_object_schema() {
        let schema = flow_object_schema();
        assert!(schema.is_object(), "the flow schema is a JSON object");
        assert!(
            schema.get("properties").is_some() || schema.get("$ref").is_some(),
            "the flow schema describes the flow object"
        );
    }

    #[test]
    fn the_messages_snapshot_carries_the_contract_version_and_every_id() {
        let snapshot = flow_messages_snapshot();
        assert_eq!(
            snapshot["contract_version"],
            super::super::model::CONTRACT_VERSION
        );
        let messages = snapshot["messages"].as_array().expect("messages array");
        assert!(!messages.is_empty(), "the registry is not empty");
        // Every entry carries a numeric id (never a copy string as the key).
        for message in messages {
            assert!(message["id"].is_u64(), "each message id is numeric");
        }
    }
}
