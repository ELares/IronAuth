// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fuzz the Keycloak realm-export parser: arbitrary input, never a panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = ironauth_importers::keycloak::map_realm(text);
    }
});
