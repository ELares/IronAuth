// SPDX-License-Identifier: MIT OR Apache-2.0

//! Small URL and time helpers: query-string percent-encoding, appending
//! parameters to a redirect URI, and epoch-microsecond conversion for the store.
//! The redirect-URI registrability rule and the exact-string comparator live in
//! [`ironauth_store::redirect`](ironauth_store) (issue #13), since the store owns
//! the registered set the comparator checks against; the authorization endpoint
//! calls them.

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
