// SPDX-License-Identifier: MIT OR Apache-2.0

//! Prints the published headless flow contract as one JSON document (issue #84): `schema`
//! (the JSON Schema for the flow object) and `messages` (the numeric message id registry
//! snapshot). Consumed by scripts/flow-schema.sh, which splits it into docs/flow-schema.json
//! and docs/flow-messages.json. Output is deterministic (schemars emits sorted maps; the
//! message registry is ordered by ascending id).

use ironauth_oidc::flow::{flow_messages_snapshot, flow_object_schema};

fn main() {
    let document = serde_json::json!({
        "schema": flow_object_schema(),
        "messages": flow_messages_snapshot(),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&document).expect("the flow contract document serializes")
    );
}
