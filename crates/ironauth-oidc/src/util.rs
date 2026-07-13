// SPDX-License-Identifier: MIT OR Apache-2.0

//! Small URL and time helpers: query-string percent-encoding, appending
//! parameters to a redirect URI, the minimal (syntactic) redirect-URI validation
//! this issue performs, and epoch-microsecond conversion for the store. The
//! strict registered-redirect matching rules are #13; here a redirect URI is
//! validated only enough that it is safe to redirect to and never carries a
//! fragment.

use std::time::SystemTime;

/// Microseconds since the Unix epoch for a wall-clock instant, saturating.
#[must_use]
pub fn epoch_micros(at: SystemTime) -> i64 {
    match at.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(delta) => i64::try_from(delta.as_micros()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

/// Percent-encode a string for use as a query-parameter value.
///
/// Everything outside the RFC 3986 unreserved set (`A-Z a-z 0-9 - . _ ~`) is
/// escaped as `%XX`. A space becomes `%20` (not `+`), which every conformant
/// parser accepts and avoids the `application/x-www-form-urlencoded` ambiguity.
#[must_use]
pub fn percent_encode_query(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            use std::fmt::Write as _;
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// Append query parameters to a base URI, choosing `?` or `&` based on whether
/// the base already has a query. Each value is percent-encoded. Parameters with a
/// `None` value are skipped, so an absent `state` is simply omitted.
#[must_use]
pub fn append_query(base: &str, params: &[(&str, Option<&str>)]) -> String {
    let mut url = base.to_owned();
    let mut has_query = base.contains('?');
    for (name, value) in params {
        let Some(value) = value else { continue };
        url.push(if has_query { '&' } else { '?' });
        has_query = true;
        url.push_str(name);
        url.push('=');
        url.push_str(&percent_encode_query(value));
    }
    url
}

/// Minimal syntactic validation of a redirect URI, performed BEFORE any redirect.
///
/// This is deliberately not the strict registered-match rule (#13 owns exact
/// matching against a client's registered set). It confirms only that the value
/// is an absolute `http`/`https` URI with a non-empty host and no fragment, so
/// that redirecting to it is safe and cannot smuggle a fragment component. An
/// invalid redirect URI never produces a redirect (the caller renders an error
/// page instead).
#[must_use]
pub fn redirect_uri_is_valid(uri: &str) -> bool {
    if uri.contains('#') {
        return false;
    }
    let rest = uri
        .strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"));
    let Some(rest) = rest else { return false };
    // The authority runs up to the first '/', '?', or end. It must be non-empty.
    let authority = rest.split(['/', '?']).next().unwrap_or("");
    !authority.is_empty()
}
