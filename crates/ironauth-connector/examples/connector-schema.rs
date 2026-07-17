// SPDX-License-Identifier: MIT OR Apache-2.0

//! Prints the published connector contract as one JSON document: `connector` (the
//! JSON Schema for [`ironauth_connector::ConnectorDefinition`]) and
//! `capability_matrix` (the JSON Schema for
//! [`ironauth_connector::CapabilityMatrix`]). Consumed by
//! scripts/connector-schema.sh, which splits it into docs/connector-schema.json
//! and docs/capability-matrix.schema.json. Output is deterministic (schemars emits
//! sorted maps).

use ironauth_connector::{capability_matrix_schema, connector_definition_schema};

fn main() {
    let document = serde_json::json!({
        "connector": connector_definition_schema(),
        "capability_matrix": capability_matrix_schema(),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&document).expect("schema document serializes")
    );
}
