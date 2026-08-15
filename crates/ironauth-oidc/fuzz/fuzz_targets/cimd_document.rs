// SPDX-License-Identifier: MIT OR Apache-2.0

//! libFuzzer target for CIMD client-ID and metadata-document parsing (issue #128).
//!
//! Both parsers here run on bytes an UNREGISTERED party chose. A CIMD `client_id` is a URL
//! the authorization server dereferences on request, and the document is whatever the
//! operator of that URL decided to serve. That inverts the usual direction: with dynamic
//! registration the server at least accepted the client first, whereas here the input
//! arrives because someone put a URL in a query string.
//!
//! So the invariant is narrow and absolute: **no input panics, and no input is accepted
//! that names something other than itself.** Every rejection is fine; a panic is a denial
//! of service reachable by anyone who can reach `/authorize`.
//!
//! Run with a nightly toolchain: `cargo +nightly fuzz run cimd_document`.

#![no_main]

use ironauth_oidc::cimd::{
    declared_max_age, is_json_document, validate_client_id_url, validate_document,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The URL parser, on arbitrary bytes. Anything that is not valid UTF-8 cannot have
    // arrived as a query parameter, so the lossy read is the honest domain.
    let text = String::from_utf8_lossy(data);
    let url_verdict = validate_client_id_url(&text);

    // The header readers. Both take caller-influenced strings and neither may panic.
    let _ = is_json_document(Some(&text));
    let _ = declared_max_age(Some(&text));

    // The document parser. Driven two ways, because the interesting property is not that
    // arbitrary bytes are refused (they are, trivially, as non-JSON) but that a document
    // is only accepted when it names the URL it came from.
    //
    // 1. Arbitrary bytes against a fixed, well-formed URL.
    const URL: &str = "https://app.example/client-metadata.json";
    if let Ok(document) = validate_document(URL, URL, data) {
        // A document that validated MUST name itself. If this ever fails, a URL can serve
        // a document claiming another party's identity, which is the whole hardening rule.
        assert_eq!(
            document.get("client_id").and_then(serde_json::Value::as_str),
            Some(URL),
            "validate_document accepted a document that does not name its own URL"
        );
    }

    // 2. The fuzzer's bytes as the URL as well, when they parsed as one. This reaches the
    //    final_url comparison with a caller-chosen value on BOTH sides, which the fixed-URL
    //    pass above can never do.
    if url_verdict.is_ok() {
        if let Ok(document) = validate_document(&text, &text, data) {
            assert_eq!(
                document.get("client_id").and_then(serde_json::Value::as_str),
                Some(text.as_ref()),
                "validate_document accepted a document that does not name its own URL"
            );
        }
        // A redirect must always be refused, whatever the bytes: the requested URL and the
        // URL that answered differ here by construction.
        assert!(
            validate_document(&text, URL, data).is_err() || text == URL,
            "validate_document accepted a body served from a different URL"
        );
    }
});
