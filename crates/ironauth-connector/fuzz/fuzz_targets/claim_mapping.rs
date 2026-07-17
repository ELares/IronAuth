// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fuzz the declarative claim-mapping evaluator (issue #75, PR C): arbitrary claims
//! JSON evaluated through a mapping never panics, always returns a TYPED result
//! (never a partial trait document), and any Ok document is itself fully
//! type-valid (the fail-closed invariant: only a fully valid document is returned).
#![no_main]
use std::collections::BTreeMap;

use ironauth_connector::{
    ClaimMapping, ClaimRule, ClaimSources, EmailSource, Quirks, TraitPointerFailure,
    TraitSchemaView, evaluate,
};
use libfuzzer_sys::fuzz_target;
use serde_json::{Map, Value};

/// A small fixed schema view mirroring `ironauth_store::TraitSchema::validate`: a set
/// of declared fields, each with a required JSON type; an undeclared field or a wrong
/// type is a per-field failure. Lets the fuzzer exercise the type-check seam without a
/// store dependency.
struct FuzzSchema;

impl TraitSchemaView for FuzzSchema {
    fn type_check(&self, document: &Value) -> Vec<TraitPointerFailure> {
        let mut failures = Vec::new();
        if let Value::Object(map) = document {
            for (field, value) in map {
                let ok = match field.as_str() {
                    "email" | "name" | "nickname" => value.is_string(),
                    "age" => value.is_i64() || value.is_u64(),
                    // Every other field is undeclared: mapping to it is a failure.
                    _ => false,
                };
                if !ok {
                    failures.push(TraitPointerFailure {
                        pointer: format!("/{field}"),
                        message: "invalid".to_string(),
                    });
                }
            }
        }
        failures
    }
}

fuzz_target!(|data: &[u8]| {
    // Interpret the input as JSON claims; a non-object input exercises the empty path.
    let claims: Map<String, Value> = match serde_json::from_slice::<Value>(data) {
        Ok(Value::Object(map)) => map,
        _ => Map::new(),
    };

    // Derive a mapping shape from the leading byte so the target explores rule variety
    // (required vs optional, an undeclared trait, the email source order, userinfo).
    let selector = data.first().copied().unwrap_or(0);
    let required = selector & 1 == 1;
    let mut traits = BTreeMap::new();
    traits.insert(
        "email".to_string(),
        ClaimRule {
            source: vec!["email".to_string(), "emails.0".to_string()],
            required,
        },
    );
    traits.insert(
        "name".to_string(),
        ClaimRule {
            source: vec!["name".to_string(), "profile.name".to_string()],
            required: false,
        },
    );
    traits.insert(
        "age".to_string(),
        ClaimRule {
            source: vec!["age".to_string()],
            required: false,
        },
    );
    if selector & 2 == 2 {
        // A trait the fuzz schema does not declare: exercises the Config path.
        traits.insert(
            "unknown".to_string(),
            ClaimRule {
                source: vec!["sub".to_string()],
                required: false,
            },
        );
    }
    let mapping = ClaimMapping {
        subject: None,
        traits,
    };
    let quirks = Quirks {
        email_source: match selector % 3 {
            0 => EmailSource::IdToken,
            1 => EmailSource::Userinfo,
            _ => EmailSource::FallbackOrder,
        },
        ..Quirks::default()
    };
    let userinfo = if selector & 4 == 4 {
        Some(&claims)
    } else {
        None
    };
    let sources = ClaimSources {
        id_token: &claims,
        userinfo,
    };
    let schema = FuzzSchema;

    // With a schema: any Ok document MUST itself pass the type check (the fail-closed
    // invariant: a returned document is fully valid, never partial). No input panics.
    if let Ok(document) = evaluate(&mapping, &quirks, sources, Some(&schema), None) {
        assert!(
            schema.type_check(&document.traits_value()).is_empty(),
            "a returned document must be fully type-valid, never partial"
        );
    }

    // Without a schema, a mapping that produces traits must fail closed (never a partial
    // document), while a traitless one succeeds. Either way, no panic.
    let _ = evaluate(
        &mapping,
        &quirks,
        ClaimSources {
            id_token: &claims,
            userinfo,
        },
        None,
        None,
    );
});
