// SPDX-License-Identifier: MIT OR Apache-2.0

//! Small URL and time helpers: query-string percent-encoding, appending
//! parameters to a redirect URI, and epoch-microsecond conversion for the store.
//! The redirect-URI registrability rule and the exact-string comparator live in
//! [`ironauth_store::redirect`](ironauth_store) (issue #13), since the store owns
//! the registered set the comparator checks against; the authorization endpoint
//! calls them.

use std::time::SystemTime;

use ironauth_store::{ActorRef, ServiceId};

/// The stable audit service-actor for an OAuth client.
///
/// Both `/authorize` (issuing a code) and `/token` (redeeming it, and revoking on
/// reuse) attribute their audit rows to the CLIENT the flow is for, not to a
/// throwaway generated identity, so the audit trail for a code and its redemption
/// share one actor. The identity is derived from the client id's PUBLIC unique
/// component (never a secret) exactly as a management key derives its audit actor,
/// so it is stable across requests and nodes without storing anything.
#[must_use]
pub fn client_service_actor(client_id: ironauth_store::StoredClientId<'_>) -> ActorRef {
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
            // The two escape digits are read through `get`, never `&value[i + 1..i + 3]`.
            // The length check above proves three BYTES exist; it proves nothing about
            // `i + 3` being a character boundary, so the direct slice PANICKED whenever a
            // multi-byte character followed the `%`. That is reachable on an
            // unauthenticated request: the federation authorize and callback legs hand
            // `query_get` the RAW wire query, and the `http` URI parser admits bytes
            // 0x80..=0xFF in a query verbatim (it requires only that the whole target be
            // valid UTF-8). `get` returns [`None`] on a non-boundary, which is not a
            // `%XX` escape at all, so it takes the same verbatim pass-through a malformed
            // escape already took. The twin in `client_auth::form_urldecode` was already
            // written this way and is unchanged; the two stay separate because form
            // decoding maps `+` to a space and this one must not.
            if let Some(Ok(byte)) = value
                .get(i + 1..i + 3)
                .map(|escape| u8::from_str_radix(escape, 16))
            {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_multibyte_character_after_a_percent_does_not_panic() {
        // Issue #419, the char-boundary panic class. `%<euro>` is three bytes after the
        // `%`, so the old length check passed and the escape slice landed INSIDE the
        // character: "end byte index 3 is not a char boundary". A non-boundary escape is
        // not a `%XX`, so it passes through verbatim exactly as `%zz` already did.
        assert_eq!(percent_decode("%\u{20ac}"), "%\u{20ac}");
        assert_eq!(percent_decode("%zz"), "%zz");

        // The whole hazard class, not only the width the crash was found with: every
        // multi-byte width, at every offset that can straddle the escape, with and
        // without surrounding text. A well-formed `%40` rides along at the end so the
        // expectation pins DECODING rather than restating the function under test: a
        // `percent_decode` that decoded nothing would leave `%40x` and fail here, and
        // `expected` is built from the input alone, never from `percent_decode`.
        for lead in 0..4 {
            for wide in ['\u{e9}', '\u{20ac}', '\u{1f600}'] {
                let prefix = "a".repeat(lead);
                let value = format!("{prefix}%{wide}tail%40x");
                let expected = format!("{prefix}%{wide}tail@x");
                assert_eq!(percent_decode(&value), expected, "{value:?}");
                assert_eq!(
                    query_get(&format!("state={value}"), "state"),
                    Some(expected),
                    "{value:?}"
                );
            }
        }

        // The same expectations written out as literals, so the pin does not depend on
        // the loop's own string building either.
        assert_eq!(percent_decode("a%\u{20ac}tail%40x"), "a%\u{20ac}tail@x");
        assert_eq!(
            query_get("state=a%\u{20ac}tail%40x", "state"),
            Some("a%\u{20ac}tail@x".to_owned())
        );
    }

    #[test]
    fn well_formed_escapes_still_decode_after_the_boundary_fix() {
        // The fix must not move a verdict: an ASCII `%XX` still decodes, a truncated
        // trailing escape still passes through, and a full round trip is unchanged.
        assert_eq!(percent_decode("ada%40example.test"), "ada@example.test");
        assert_eq!(percent_decode("%E2%82%AC"), "\u{20ac}");
        assert_eq!(percent_decode("%4"), "%4");
        assert_eq!(percent_decode("%"), "%");
        assert_eq!(
            percent_decode(&percent_encode_query("a b/c?d=e&f\u{20ac}")),
            "a b/c?d=e&f\u{20ac}"
        );
    }

    #[test]
    fn a_raw_query_string_carrying_a_multibyte_escape_reads_back() {
        // The reachable shape: the federation authorize and callback legs hand
        // `query_get` the RAW wire query, and the `http` URI parser admits bytes
        // 0x80..=0xFF in a query. This is the exact call that panicked.
        let query = "return_to=%\u{20ac}&code=abc";
        assert_eq!(query_get(query, "return_to"), Some("%\u{20ac}".to_owned()));
        assert_eq!(query_get(query, "code"), Some("abc".to_owned()));
        assert_eq!(query_get(query, "absent"), None);
    }
}
