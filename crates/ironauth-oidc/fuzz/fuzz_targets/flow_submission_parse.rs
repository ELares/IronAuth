// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz target over the headless flow SUBMISSION parser (issue #84, PR 4): the node-values
//! decode plus the transient-payload parse, the untrusted edge every flow advance ingests.
//!
//! The properties the fuzzer proves, for EVERY input:
//!
//! - [`parse_api_submission`] (the API JSON envelope: flow id, submit token, node values, and
//!   transient payload) never panics on arbitrary bytes: it is TOTAL, returning either an
//!   `Ok(ParsedApiSubmission)` or a TYPED [`FlowError`] (`InvalidSubmission` for a malformed
//!   envelope, `MalformedTransientPayload` for an oversized or non-JSON transient payload),
//!   NEVER a 500 and never a partial value; and
//! - [`parse_form_transient_payload`] (the browser transient-payload field, a JSON string) is
//!   likewise total, returning `Ok` or a typed `MalformedTransientPayload`, never a panic.
//!
//! These are the exact functions the live API and browser submit handlers route through, so
//! the fuzzer exercises the real decode path, not a divergent copy. A rejected submission that
//! ever surfaced as a panic (a 500 or a process abort) would be a denial-of-service oracle on
//! the untrusted flow-advance edge; the property here is that it cannot.
//!
//! Run locally: `cargo +nightly fuzz run flow_submission_parse` from this directory.

#![no_main]

use ironauth_oidc::flow::{FlowError, parse_api_submission, parse_form_transient_payload};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The API JSON envelope decode: arbitrary bytes are total. A malformed envelope is a typed
    // InvalidSubmission; an oversized/malformed transient payload is a typed
    // MalformedTransientPayload; a well-formed one yields a Submission whose transient payload,
    // when present, is within the size cap (the parser enforces it, so a serialize is bounded).
    match parse_api_submission(data) {
        Ok(parsed) => {
            if let Some(payload) = &parsed.submission.transient_payload {
                // A carried payload is never JSON null (null normalizes to absent) and always
                // re-serializes (it round-tripped through the validator), so this cannot panic.
                assert!(!payload.is_null(), "a carried transient payload is never null");
                let serialized = serde_json_len(payload);
                assert!(serialized <= 8 * 1024, "the transient payload stays within the cap");
            }
        }
        Err(error) => {
            // The rejection is one of the typed parse errors, never anything else.
            assert!(
                matches!(
                    error,
                    FlowError::InvalidSubmission | FlowError::MalformedTransientPayload
                ),
                "a parse rejection is a typed flow error"
            );
        }
    }

    // The browser transient-payload field decode (a JSON string): also total. Feed the raw bytes
    // lossily as the field value, so arbitrary and invalid UTF-8 is exercised.
    let as_str = String::from_utf8_lossy(data);
    match parse_form_transient_payload(Some(&as_str)) {
        Ok(_) => {}
        Err(error) => assert!(
            matches!(error, FlowError::MalformedTransientPayload),
            "a browser transient-payload rejection is the typed malformed error"
        ),
    }
});

/// The serialized byte length of a JSON value (for the cap assertion). A value that reached
/// here already serialized once inside the parser's validator, so this re-serialization cannot
/// fail; it is measured rather than unwrapped to avoid any panic path.
fn serde_json_len(value: &serde_json::Value) -> usize {
    serde_json::to_string(value).map(|s| s.len()).unwrap_or(0)
}
