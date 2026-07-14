// SPDX-License-Identifier: MIT OR Apache-2.0

//! The bootstrap session cookie (issue #20).
//!
//! The session is an opaque, server-side row (see `ironauth_store`); the cookie
//! carries only its identifier. The cookie is hardened by construction:
//!
//! - the `__Host-` name prefix, which a conformant browser accepts ONLY when the
//!   cookie is `Secure`, has `Path=/`, and carries no `Domain`, so it cannot be
//!   set over plaintext, scoped to a path, or shared across subdomains (it pins
//!   the cookie to exactly this host over HTTPS);
//! - `Secure` (never sent over plaintext) and `HttpOnly` (unreadable from
//!   script, so an XSS cannot exfiltrate the session);
//! - `SameSite=Lax`, so the cookie is withheld from cross-site subrequests.
//!
//! The value is the `ses_` session identifier, which is URL-safe base64 and
//! embeds its `(tenant, environment)` scope, so the authorization endpoint
//! recovers the scope from the cookie without a lookup and a session from one
//! scope never resolves under another.
//!
//! The value is kept a SMALL opaque identifier (the `ses_` id, never a multi-KB
//! state blob), so the `Set-Cookie` header can never bloat into the request-header
//! limit class (the nextjs-auth0 431 failure); a test bounds its size. The M4 model
//! (issue #32) adds authoritative rotation, fleet operations, and a CHIPS
//! `Partitioned` toggle for embedded-widget (cross-site) scenarios.

use std::time::Duration;

/// The session cookie name. The `__Host-` prefix is load-bearing: a conformant
/// browser rejects a `__Host-` cookie that is not `Secure`, not `Path=/`, or
/// carries a `Domain`, so the prefix enforces those attributes browser-side.
pub const SESSION_COOKIE: &str = "__Host-ironauth_session";

/// The internal request header carrying the POLICY-RESOLVED client IP: the input of
/// the OFF-BY-DEFAULT peer-IP session binding (issue #32). Defined once in the config
/// crate that both the server (which stamps it) and this crate (which reads it) share,
/// and re-exported here for the session surfaces. Never client input: the server's
/// middleware overwrites it on every request.
pub use ironauth_config::PEER_IP_HEADER;

/// Build the `Set-Cookie` header value that establishes a session.
///
/// The cookie keeps every hardening attribute by construction: the `__Host-` name
/// prefix, `Secure`, `HttpOnly`, and `SameSite=Lax`. `Max-Age` matches the
/// server-side session lifetime so the browser drops the cookie when the row would
/// have expired anyway; the server still enforces expiry authoritatively at read
/// time.
///
/// `partitioned` adds the CHIPS `Partitioned` attribute (issue #32) for embedded
/// widget scenarios, so a cross-site embed gets a per-top-level-site partitioned
/// cookie. It is OFF by default: it NEVER drops `SameSite` and NEVER breaks the
/// `__Host-` prefix (both remain present), it only ADDS `Partitioned`.
#[must_use]
pub fn build_set_cookie(session_id: &str, ttl: Duration, partitioned: bool) -> String {
    let max_age = i64::try_from(ttl.as_secs()).unwrap_or(i64::MAX);
    let mut cookie = format!(
        "{SESSION_COOKIE}={session_id}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}"
    );
    if partitioned {
        cookie.push_str("; Partitioned");
    }
    cookie
}

/// Build the `Set-Cookie` header value that CLEARS the session cookie at logout
/// (issue #32): the same `__Host-`/`Secure`/`HttpOnly`/`SameSite` hardened cookie
/// with an empty value and `Max-Age=0`, so a conformant browser drops it
/// immediately. `partitioned` keeps the CHIPS attribute consistent with how the
/// cookie was set, so the clear targets the same partitioned jar.
#[must_use]
pub fn clear_set_cookie(partitioned: bool) -> String {
    let mut cookie =
        format!("{SESSION_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0");
    if partitioned {
        cookie.push_str("; Partitioned");
    }
    cookie
}

/// Extract the session-cookie value from a `Cookie` header value, if present. The
/// header is a `; `-separated list of `name=value` pairs; the first pair whose
/// name matches [`SESSION_COOKIE`] wins. A missing header or a missing pair is
/// [`None`], which the caller treats as unauthenticated.
#[must_use]
pub fn session_value_from_cookie_header(header: Option<&str>) -> Option<&str> {
    let header = header?;
    header.split(';').find_map(|pair| {
        let (name, value) = pair.trim().split_once('=')?;
        (name == SESSION_COOKIE).then_some(value)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_cookie_carries_the_host_prefix_and_all_hardening_attributes() {
        let cookie = build_set_cookie("ses_abc", Duration::from_secs(3600), false);
        assert!(cookie.starts_with("__Host-ironauth_session=ses_abc; "));
        for attr in [
            "Path=/",
            "Secure",
            "HttpOnly",
            "SameSite=Lax",
            "Max-Age=3600",
        ] {
            assert!(cookie.contains(attr), "missing {attr}: {cookie}");
        }
        // A __Host- cookie must never carry a Domain.
        assert!(!cookie.contains("Domain"), "{cookie}");
        // Off by default: no CHIPS Partitioned attribute.
        assert!(!cookie.contains("Partitioned"), "{cookie}");
    }

    #[test]
    fn partitioned_toggle_adds_chips_without_dropping_any_hardening() {
        // The CHIPS toggle (issue #32) ADDS Partitioned; it must not drop SameSite
        // and must not break the __Host- prefix (both stay present).
        let cookie = build_set_cookie("ses_abc", Duration::from_secs(3600), true);
        assert!(cookie.starts_with("__Host-ironauth_session=ses_abc; "));
        assert!(cookie.contains("Partitioned"), "{cookie}");
        for attr in ["Path=/", "Secure", "HttpOnly", "SameSite=Lax"] {
            assert!(cookie.contains(attr), "missing {attr}: {cookie}");
        }
        assert!(!cookie.contains("Domain"), "{cookie}");
    }

    #[test]
    fn clear_cookie_expires_immediately_and_stays_hardened() {
        // Logout (issue #32) clears the cookie with Max-Age=0 and an empty value,
        // keeping the __Host-/Secure/HttpOnly/SameSite hardening so a conformant
        // browser accepts and drops it.
        let cookie = clear_set_cookie(false);
        assert!(cookie.starts_with("__Host-ironauth_session=; "));
        for attr in ["Path=/", "Secure", "HttpOnly", "SameSite=Lax", "Max-Age=0"] {
            assert!(cookie.contains(attr), "missing {attr}: {cookie}");
        }
        assert!(!cookie.contains("Domain"), "{cookie}");
        // Partitioned mirrors how the cookie was set.
        assert!(clear_set_cookie(true).contains("Partitioned"));
    }

    #[test]
    fn cookie_payload_stays_a_small_opaque_id_below_header_limits() {
        // The cookie value is the small opaque ses_ id, never a multi-KB state blob
        // (issue #32): bound the whole Set-Cookie header well below the common 4 KB
        // per-cookie and 8 KB request-header limits, so the nextjs-auth0 431 class
        // (multi-KB chunked cookies) is structurally impossible. A ses_ id is a fixed
        // prefix plus a scope and a 128-bit component; even a generous spelling of it
        // stays tiny.
        let generous_id = format!("ses_{}", "a".repeat(200));
        let cookie = build_set_cookie(&generous_id, Duration::from_secs(3600), true);
        assert!(
            cookie.len() < 512,
            "the session cookie must stay a small opaque id, got {} bytes: {cookie}",
            cookie.len()
        );
    }

    #[test]
    fn parses_the_session_value_among_other_cookies() {
        assert_eq!(
            session_value_from_cookie_header(Some("a=1; __Host-ironauth_session=ses_xyz; b=2")),
            Some("ses_xyz")
        );
        assert_eq!(
            session_value_from_cookie_header(Some("__Host-ironauth_session=ses_only")),
            Some("ses_only")
        );
    }

    #[test]
    fn absent_cookie_and_absent_header_are_none() {
        assert_eq!(session_value_from_cookie_header(None), None);
        assert_eq!(
            session_value_from_cookie_header(Some("other=1; another=2")),
            None
        );
        // A same-suffix decoy name must not match.
        assert_eq!(
            session_value_from_cookie_header(Some("ironauth_session=nope")),
            None
        );
    }
}
