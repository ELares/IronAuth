// SPDX-License-Identifier: MIT OR Apache-2.0

//! The published journey artifact JSON Schema (issue #92, PR 1): the draft 2020-12 schema for
//! the [`Journey`] document, GENERATED from the artifact structs themselves (via `schemars`,
//! exactly like the `ironauth-oidc` flow contract), so the committed `docs/journey-schema.json`
//! can never drift from the code. `scripts/journey-schema.sh` regenerates and diffs it as a CI
//! gate. This is a schema GENERATOR only; the authoritative load-time check is
//! [`crate::validate`].

use schemars::schema_for;
use serde_json::Value;

use crate::artifact::Journey;

/// The JSON Schema for the journey artifact (issue #92), generated from the [`Journey`] type.
/// Deterministic: `schemars` emits sorted maps, so the same code always produces byte-identical
/// output, which the regeneration gate relies on.
///
/// # Panics
///
/// Panics only if the derived schema fails to serialize to JSON, a compile-time impossibility
/// for these types (a build-breaking programming error, never a runtime one).
#[must_use]
pub fn journey_object_schema() -> Value {
    serde_json::to_value(schema_for!(Journey)).expect("the journey schema serializes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::StepKind;

    #[test]
    fn the_schema_is_a_draft_2020_12_object_for_the_journey() {
        let schema = journey_object_schema();
        assert_eq!(
            schema.get("$schema").and_then(Value::as_str),
            Some("https://json-schema.org/draft/2020-12/schema")
        );
        // The top-level document is the Journey object with its required fields present.
        assert_eq!(schema.get("title").and_then(Value::as_str), Some("Journey"));
        let required = schema
            .get("required")
            .and_then(Value::as_array)
            .expect("the journey has required fields");
        for field in [
            "schema_version",
            "id",
            "engine_version",
            "entry",
            "steps",
            "transitions",
        ] {
            assert!(
                required.iter().any(|value| value.as_str() == Some(field)),
                "missing required field {field}"
            );
        }
        // deny_unknown_fields on the artifact structs is mirrored in the schema, so a document
        // with an extra or misspelled property is rejected at the schema level too.
        assert_eq!(
            schema.get("additionalProperties"),
            Some(&Value::Bool(false)),
            "the Journey schema must forbid additional properties"
        );
        let step = schema
            .get("$defs")
            .and_then(|defs| defs.get("Step"))
            .expect("the Step definition is published");
        assert_eq!(
            step.get("additionalProperties"),
            Some(&Value::Bool(false)),
            "the Step schema must forbid additional properties"
        );
    }

    #[test]
    fn the_step_kind_schema_lists_exactly_the_closed_built_in_set() {
        // The published schema locks the closed step-kind vocabulary: a schema-level check
        // rejects an unknown kind even though the Rust parse is tolerant (to yield a pointer).
        let schema = journey_object_schema();
        let step_kind = schema
            .get("$defs")
            .and_then(|defs| defs.get("StepKind"))
            .expect("the StepKind definition is published");
        let published: Vec<&str> = step_kind
            .get("enum")
            .and_then(Value::as_array)
            .expect("StepKind is an enum of strings")
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(published, StepKind::BUILT_IN);
    }
}
