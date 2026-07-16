// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fuzz the Auth0 export + hash-export parsers: arbitrary input, never a panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        // The same bytes drive both the profile export and the joined hash export.
        let _ = ironauth_importers::auth0::map_export(text, Some(text));
    }
});
