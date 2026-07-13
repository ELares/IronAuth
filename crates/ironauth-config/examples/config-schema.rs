// SPDX-License-Identifier: MIT OR Apache-2.0

//! Prints the machine-readable config contract as one JSON document:
//! `schema` (the JSON Schema for [`ironauth_config::Config`]) plus
//! `features` (the built-in feature registry with maturity metadata).
//! Consumed by scripts/config-schema.sh, which splits it into
//! docs/config-schema.json and docs/CONFIG.md. Output is deterministic:
//! registry iteration is name-ordered and JSON maps serialize sorted.

use ironauth_config::{Config, FeatureRegistry, Maturity};

fn main() {
    let features: Vec<serde_json::Value> = FeatureRegistry::builtin()
        .iter()
        .map(|feature| {
            let (maturity, version, changelog) = match feature.maturity() {
                Maturity::Experimental { version, changelog } => {
                    ("experimental", Some(version), Some(changelog))
                }
                Maturity::Preview => ("preview", None, None),
                Maturity::Supported => ("supported", None, None),
            };
            serde_json::json!({
                "name": feature.name(),
                "maturity": maturity,
                "version": version,
                "changelog": changelog,
                "doc": feature.doc(),
                "default_enabled": feature.default_enabled(),
            })
        })
        .collect();

    let document = serde_json::json!({
        "schema": Config::json_schema(),
        "features": features,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&document).expect("schema document serializes")
    );
}
