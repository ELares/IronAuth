// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fuzz the connector-definition deserializer and semantic validator: arbitrary
//! bytes never panic, and a definition that fails to validate is REJECTED, never
//! silently accepted.
#![no_main]
use ironauth_connector::ConnectorDefinition;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Phase one: deserialization. Arbitrary (malformed) bytes must never panic;
    // an unknown key or a malformed endpoints one-of is an Err, not a crash.
    if let Ok(definition) = serde_json::from_slice::<ConnectorDefinition>(data) {
        // Phase two: the semantic validator must never panic on a parsed value,
        // and its verdict is total (Ok or a non-empty error list). A definition
        // that fails to validate is rejected, never accepted.
        if let Err(errors) = definition.validate() {
            assert!(!errors.is_empty(), "a rejection must carry at least one error");
        }
        // The secret-free projection must never carry the client_secret field.
        let projection = definition.secret_free_json();
        if let Some(object) = projection.as_object() {
            assert!(
                !object.contains_key("client_secret"),
                "the secret-free projection must omit client_secret"
            );
        }
    }
});
