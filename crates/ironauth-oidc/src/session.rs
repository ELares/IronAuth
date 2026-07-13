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
//! This is the MINIMAL bootstrap session; the real two-tier model with rotation
//! and fleet operations is M4.

use std::time::Duration;

/// The session cookie name. The `__Host-` prefix is load-bearing: a conformant
/// browser rejects a `__Host-` cookie that is not `Secure`, not `Path=/`, or
/// carries a `Domain`, so the prefix enforces those attributes browser-side.
pub const SESSION_COOKIE: &str = "__Host-ironauth_session";

/// Build the `Set-Cookie` header value that establishes a session.
///
/// `Max-Age` matches the server-side session lifetime so the browser drops the
/// cookie when the row would have expired anyway; the server still enforces
/// expiry authoritatively at read time.
#[must_use]
pub fn build_set_cookie(session_id: &str, ttl: Duration) -> String {
    let max_age = i64::try_from(ttl.as_secs()).unwrap_or(i64::MAX);
    format!(
        "{SESSION_COOKIE}={session_id}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}"
    )
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
        let cookie = build_set_cookie("ses_abc", Duration::from_secs(3600));
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
