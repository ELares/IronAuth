// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz target over the branding rich-text SANITIZER (issue #86): the ONE place any branding
//! rich text becomes safe markup, and the security core of safe branding (the Casdoor
//! stored-XSS class the issue calls out).
//!
//! The properties the fuzzer proves, for EVERY input (arbitrary, possibly invalid UTF-8):
//!
//! - [`sanitize`] never panics: it is TOTAL over arbitrary bytes (fed lossily as text), always
//!   returning a `SanitizedRichText`, never a process abort (a panic here would be a
//!   denial-of-service oracle on the branding ingest edge); and
//! - the sanitized output is INERT: it emits none of the dangerous elements (`<script`,
//!   `<img`, `<style`, `<svg`, `<iframe`, ...) and, inside every real `<...>` tag region,
//!   carries no `on*` event handler, no `style=` attribute, and only an `https` `href` (the
//!   one attribute the allowlist permits) -- so no crafted input can smuggle executable
//!   markup through the allowlist. The check inspects only tag regions, not inert escaped
//!   text (in the output a text `<` is `&lt;` and a text `"` is `&quot;`, so a real tag /
//!   attribute can only appear inside `<...>`), so an escaped `onerror=` in text is not a
//!   false positive; and
//! - [`sanitize`] is IDEMPOTENT: re-sanitizing its own output is a fixed point, so re-running
//!   the sanitizer on a stored value (defense in depth on read) never changes a safe value.
//!
//! This is the exact function the live branding ingest and render paths route through, so the
//! fuzzer exercises the real allowlist sanitizer, not a divergent copy. The seed corpus is the
//! Casdoor-class bypass corpus asserted every-PR in the crate's `branding::sanitize` unit tests.
//!
//! Run locally: `cargo +nightly fuzz run branding_sanitize` from this directory.

#![no_main]

use ironauth_oidc::branding::sanitize;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Arbitrary (possibly invalid UTF-8) bytes are total input to the sanitizer.
    let input = String::from_utf8_lossy(data);
    let clean = sanitize(&input);
    assert_inert(clean.as_str());

    // Idempotence: sanitizing already-sanitized output is a fixed point.
    let twice = sanitize(clean.as_str());
    assert_eq!(
        clean.as_str(),
        twice.as_str(),
        "sanitize must be idempotent"
    );
    assert_inert(twice.as_str());
});

/// Assert a sanitized fragment is INERT, robustly against inert escaped TEXT: it emits no
/// dangerous element, and inside every real `<...>` tag region there is no `on*` handler, no
/// `style=` attribute, and any `href` value is `https`.
fn assert_inert(out: &str) {
    let lower = out.to_ascii_lowercase();
    for tag in [
        "<script",
        "</script",
        "<style",
        "<svg",
        "<iframe",
        "<object",
        "<embed",
        "<img",
        "<math",
        "<meta",
        "<base",
        "<link",
        "<form",
        "<noscript",
        "<template",
        "<textarea",
        "<foreignobject",
    ] {
        assert!(
            !lower.contains(tag),
            "sanitized output emitted a dangerous element {tag:?}: {out:?}"
        );
    }
    let mut cursor = 0;
    while let Some(rel) = lower[cursor..].find('<') {
        let start = cursor + rel;
        // ammonia escapes a `>` inside an attribute value to `&gt;`, so the first `>` always
        // ends the tag; the region is a complete `<...>` opening.
        let end = lower[start..].find('>').map_or(lower.len(), |e| start + e);
        assert_tag_region_inert(&lower[start..end], out);
        cursor = end + 1;
        if cursor >= lower.len() {
            break;
        }
    }
}

/// Assert one `<...>` tag region carries no `on*` handler and no `style` attribute NAME, and
/// that any `href` value is https. QUOTE-AWARE: an inert substring inside a quoted attribute
/// VALUE (a mangled URL containing ` onerror=`, say) cannot false-positive, because an
/// attribute NAME is always outside quotes.
fn assert_tag_region_inert(region: &str, out: &str) {
    // The attribute-name skeleton: the region with every double-quoted value removed.
    let mut skeleton = String::with_capacity(region.len());
    let mut in_quote = false;
    for ch in region.chars() {
        if ch == '"' {
            in_quote = !in_quote;
            continue;
        }
        if !in_quote {
            skeleton.push(ch);
        }
    }
    assert!(
        !skeleton.contains(" on"),
        "sanitized output left an on* handler attribute: {out:?}"
    );
    assert!(
        !skeleton.contains("style="),
        "sanitized output left a style attribute: {out:?}"
    );
    if let Some(h) = region.find("href=\"") {
        // The href VALUE runs to the next quote. Determine its EFFECTIVE scheme the way the
        // WHATWG URL parser (which ammonia uses) does: remove every ASCII tab and newline
        // from anywhere in the value, then strip the leading C0 control and ASCII whitespace.
        // So a cosmetic control-char prefix or a scheme split by newlines
        // (`http\ns\n:l` -> `https:l`) on an inert https URL is not a false positive, while a
        // genuine non-https scheme (a split `j\nava\nscript:`) still fails. ammonia was
        // verified to REJECT every such scripting/data scheme, so only real https survives.
        let raw = region[h + "href=\"".len()..].split('"').next().unwrap_or("");
        let stripped: String = raw
            .chars()
            .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
            .collect();
        let value =
            stripped.trim_start_matches(|c: char| c.is_ascii_control() || c.is_ascii_whitespace());
        assert!(
            value.starts_with("https"),
            "sanitized output left a non-https href: {out:?}"
        );
    }
}
