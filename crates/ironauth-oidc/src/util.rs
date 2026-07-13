// SPDX-License-Identifier: MIT OR Apache-2.0

//! Small URL and time helpers: query-string percent-encoding, appending
//! parameters to a redirect URI, the minimal (syntactic) redirect-URI validation
//! this issue performs, and epoch-microsecond conversion for the store. The
//! strict registered-redirect matching rules are #13; here a redirect URI is
//! validated only enough that it is safe to redirect to and never carries a
//! fragment.

use std::time::SystemTime;

use ironauth_store::{ActorRef, ClientId, ServiceId};

/// The stable audit service-actor for an OAuth client.
///
/// Both `/authorize` (issuing a code) and `/token` (redeeming it, and revoking on
/// reuse) attribute their audit rows to the CLIENT the flow is for, not to a
/// throwaway generated identity, so the audit trail for a code and its redemption
/// share one actor. The identity is derived from the client id's PUBLIC unique
/// component (never a secret) exactly as a management key derives its audit actor,
/// so it is stable across requests and nodes without storing anything.
#[must_use]
pub fn client_service_actor(client_id: &ClientId) -> ActorRef {
    ActorRef::service(ServiceId::from_seed_bytes(client_id.unique_bytes()))
}

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

/// Percent-decode a query/form value (`%XX` becomes the byte). A malformed
/// trailing escape is passed through verbatim. This is the inverse of
/// [`percent_encode_query`] for the values IronAuth itself emits (which use `%20`
/// for a space, never `+`).
#[must_use]
pub fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 3 <= bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&value[i + 1..i + 3], 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Read a single parameter from a raw query string (the part after `?`),
/// percent-decoding its value. The first matching key wins; an absent key is
/// [`None`].
#[must_use]
pub fn query_get(query: &str, name: &str) -> Option<String> {
    for pair in query.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            if key == name {
                return Some(percent_decode(value));
            }
        }
    }
    None
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
/// is safe to place in a `Location` header and redirect to:
///
/// - Every byte is printable ASCII (`0x21..=0x7E`). This rejects a raw space,
///   any control character (CR, LF, TAB, NUL), and any non-ASCII byte, so the
///   value cannot smuggle a header-splitting `\r\n`, hide whitespace, or carry a
///   Unicode look-alike authority. A conformant redirect URI is already
///   percent-encoded, so nothing legitimate is excluded.
/// - It carries no fragment (`#`): a fragment on a redirect target is a smuggling
///   surface and is never needed here.
/// - It is an absolute `http`/`https` URI with a non-empty authority.
///
/// An invalid redirect URI never produces a redirect (the caller renders an
/// error page instead).
#[must_use]
pub fn redirect_uri_is_valid(uri: &str) -> bool {
    // Reject anything that is not printable ASCII: control characters (including
    // CR/LF used for header splitting), a raw space, DEL, and every non-ASCII
    // byte. A well-formed redirect URI is percent-encoded and so is unaffected.
    if !uri.bytes().all(|byte| (0x21..=0x7E).contains(&byte)) {
        return false;
    }
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

#[cfg(test)]
mod tests {
    use super::redirect_uri_is_valid;

    #[test]
    fn accepts_well_formed_absolute_http_and_https() {
        assert!(redirect_uri_is_valid("https://client.test/cb"));
        assert!(redirect_uri_is_valid("http://localhost:8080/callback?x=1"));
        // A percent-encoded space is fine (nothing raw to smuggle).
        assert!(redirect_uri_is_valid("https://client.test/a%20b"));
    }

    #[test]
    fn rejects_control_whitespace_and_non_ascii() {
        // A raw space, a tab, and the CR/LF header-splitting pair are all refused.
        assert!(!redirect_uri_is_valid("https://client.test/a b"));
        assert!(!redirect_uri_is_valid("https://client.test/a\tb"));
        assert!(!redirect_uri_is_valid(
            "https://client.test/cb\r\nSet-Cookie: x=y"
        ));
        assert!(!redirect_uri_is_valid("https://client.test/cb\n"));
        // A NUL and a DEL are control characters.
        assert!(!redirect_uri_is_valid("https://client.test/cb\0"));
        assert!(!redirect_uri_is_valid("https://client.test/cb\u{7f}"));
        // A non-ASCII (Unicode look-alike) authority is refused.
        assert!(!redirect_uri_is_valid("https://client\u{0430}.test/cb"));
    }

    #[test]
    fn rejects_fragment_relative_and_empty_authority() {
        assert!(!redirect_uri_is_valid("https://client.test/cb#frag"));
        assert!(!redirect_uri_is_valid("/relative/path"));
        assert!(!redirect_uri_is_valid("ftp://client.test/cb"));
        assert!(!redirect_uri_is_valid("https:///no-host"));
        assert!(!redirect_uri_is_valid(""));
    }
}
