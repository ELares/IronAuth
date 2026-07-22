// SPDX-License-Identifier: MIT OR Apache-2.0

//! Prints the published journey artifact JSON Schema as one JSON document (issue #92).
//! Consumed by scripts/journey-schema.sh, which wraps it with the generated-file banner and
//! writes docs/journey-schema.json. Output is deterministic (schemars emits sorted maps), so a
//! fresh run produces zero diff and the CI gate fails a stale committed schema.

use ironauth_journey::journey_object_schema;

fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(&journey_object_schema())
            .expect("the journey schema document serializes")
    );
}
