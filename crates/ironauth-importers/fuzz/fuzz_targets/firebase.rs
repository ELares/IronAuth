// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fuzz the Firebase auth:export parser: arbitrary input, never a panic.
#![no_main]
use ironauth_importers::firebase::{self, FirebaseHashParams};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        // Fixed, structurally valid project parameters; the interesting behavior is
        // in the document parse and the per-user hash re-encoding.
        let params = FirebaseHashParams::new("AAAA", "Bw==", 8, 14);
        let _ = firebase::map_export(text, &params);
    }
});
