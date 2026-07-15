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
//! - `SameSite=Lax` by default, so the cookie is withheld from cross-site
//!   subrequests. The OFF-BY-DEFAULT CHIPS toggle swaps this for the real CHIPS
//!   shape (`SameSite=None; Partitioned`), which is double-keyed to the top-level
//!   site; see [`build_set_cookie`].
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

/// The OP browser-state cookie name (OIDC Session Management 1.0, issue #39). It
/// deliberately does NOT carry the `__Host-` prefix and is NOT `HttpOnly`, because
/// the `check_session_iframe` script must read it via `document.cookie` from inside
/// an RP-embedded, cross-site (third-party) iframe. Its value is the one-way
/// `op_browser_state` digest (see [`crate::session_mgmt::op_browser_state`]), never
/// the session id, so a script-readable, cross-site cookie leaks nothing.
pub const OP_BROWSER_STATE_COOKIE: &str = "__ironauth_opbs";

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
/// `partitioned` switches the cookie to the real CHIPS shape (issue #32) for the
/// embedded-widget (cross-site iframe) scenario. It is OFF by default.
///
/// CHIPS is `Secure; SameSite=None; Partitioned`. `SameSite=None` is the load-bearing
/// half: `Partitioned` alone, bolted onto a `SameSite=Lax` cookie, is INERT, because a
/// conformant browser withholds a `Lax` cookie from exactly the cross-site
/// subrequests CHIPS exists to serve. So the toggle moves `SameSite` to `None` and adds
/// `Partitioned` together, or it does neither.
///
/// This is not a weakening. `Partitioned` is what makes `SameSite=None` safe here: the
/// cookie is double-keyed to the top-level site, so an embed on `evil.example` gets a
/// DIFFERENT jar than the same embed on the legitimate site and cannot read this
/// session. The `__Host-` prefix (and `Secure`, `HttpOnly`, `Path=/`, no `Domain`)
/// survive in BOTH shapes: `__Host-` remains valid with `SameSite=None`, and CSRF
/// defense on the interactive endpoints does not rest on `SameSite` alone (the
/// same-origin check does).
#[must_use]
pub fn build_set_cookie(session_id: &str, ttl: Duration, partitioned: bool) -> String {
    let max_age = i64::try_from(ttl.as_secs()).unwrap_or(i64::MAX);
    format!(
        "{SESSION_COOKIE}={session_id}; Path=/; Secure; HttpOnly; SameSite={}; \
         Max-Age={max_age}{}",
        same_site(partitioned),
        partitioned_suffix(partitioned),
    )
}

/// The `SameSite` value for the cookie: `None` under the CHIPS toggle (so the cookie
/// actually rides the cross-site subrequests it is partitioned for), `Lax` otherwise.
fn same_site(partitioned: bool) -> &'static str {
    if partitioned { "None" } else { "Lax" }
}

/// The trailing `; Partitioned` attribute under the CHIPS toggle, empty otherwise.
fn partitioned_suffix(partitioned: bool) -> &'static str {
    if partitioned { "; Partitioned" } else { "" }
}

/// Build the `Set-Cookie` header value that CLEARS the session cookie at logout
/// (issue #32): the same `__Host-`/`Secure`/`HttpOnly`/`SameSite` hardened cookie
/// with an empty value and `Max-Age=0`, so a conformant browser drops it
/// immediately. `partitioned` MUST match how the cookie was set: a clear has to name
/// the same `SameSite` and `Partitioned` attributes to target the same jar, or the
/// partitioned cookie would survive the logout.
#[must_use]
pub fn clear_set_cookie(partitioned: bool) -> String {
    format!(
        "{SESSION_COOKIE}=; Path=/; Secure; HttpOnly; SameSite={}; Max-Age=0{}",
        same_site(partitioned),
        partitioned_suffix(partitioned),
    )
}

/// Build the `Set-Cookie` header that publishes the OP browser state to the
/// `check_session_iframe` (OIDC Session Management 1.0, issue #39).
///
/// This cookie is the load-bearing half of session management: the iframe recomputes
/// `session_state` from `client_id`, its own `origin`, this cookie, and the echoed
/// salt, and can only ever answer `unchanged` when the value it reads here matches
/// the `op_browser_state` the authorization response baked into `session_state`.
/// Without this cookie the iframe reads nothing and answers `changed` forever, so an
/// RP polling `check_session` re-authenticates in a loop (spec section 5.1).
///
/// Its attributes are deliberately the OPPOSITE of the session cookie's on three
/// axes, and identical on the rest:
///
/// - NOT `HttpOnly`: the iframe script reads it with `document.cookie`. This is safe
///   because the value is the one-way `op_browser_state` digest, never the session id;
/// - `SameSite=None` (and therefore `Secure`): the iframe is embedded by the RP, so
///   the cookie is read in a third-party context and must ride the cross-site request;
/// - NO `__Host-` prefix: `__Host-` is compatible with `SameSite=None`, but the value
///   is a public digest with none of the session cookie's confidentiality needs, so
///   the prefix would only add friction without buying secrecy the digest already has.
///
/// `Max-Age` matches the session lifetime, so the browser drops it when the session
/// row would have expired anyway; [`clear_op_browser_state_cookie`] expires it at
/// logout.
#[must_use]
pub fn build_op_browser_state_cookie(op_browser_state: &str, ttl: Duration) -> String {
    let max_age = i64::try_from(ttl.as_secs()).unwrap_or(i64::MAX);
    format!(
        "{OP_BROWSER_STATE_COOKIE}={op_browser_state}; Path=/; Secure; SameSite=None; \
         Max-Age={max_age}"
    )
}

/// Build the `Set-Cookie` header that CLEARS the OP browser-state cookie at logout
/// (issue #39): the same name and attributes with an empty value and `Max-Age=0`, so
/// a conformant browser drops it and the `check_session_iframe` flips to `changed` for
/// the ended session exactly as the spec intends. It names the same
/// `Path`/`Secure`/`SameSite` attributes as [`build_op_browser_state_cookie`] so it
/// targets the same jar.
#[must_use]
pub fn clear_op_browser_state_cookie() -> String {
    format!("{OP_BROWSER_STATE_COOKIE}=; Path=/; Secure; SameSite=None; Max-Age=0")
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
    fn partitioned_toggle_emits_the_real_chips_shape_and_keeps_every_hardening_attribute() {
        // The CHIPS toggle (issue #32) must emit the shape a conformant browser
        // actually honors on a cross-site embedded subrequest: Secure + SameSite=None
        // + Partitioned. Appending Partitioned to a SameSite=Lax cookie (what this
        // used to do) is INERT: the browser withholds a Lax cookie from exactly the
        // subrequests CHIPS exists to serve, so the toggle bought nothing.
        let cookie = build_set_cookie("ses_abc", Duration::from_secs(3600), true);
        assert!(cookie.starts_with("__Host-ironauth_session=ses_abc; "));
        for attr in [
            "Path=/",
            "Secure",
            "HttpOnly",
            "SameSite=None",
            "Partitioned",
            "Max-Age=3600",
        ] {
            assert!(cookie.contains(attr), "missing {attr}: {cookie}");
        }
        // SameSite=None is the whole point of the toggle: Lax must be GONE, or the
        // cookie is still withheld cross-site and Partitioned stays decorative.
        assert!(
            !cookie.contains("SameSite=Lax"),
            "the CHIPS toggle must move SameSite off Lax: {cookie}"
        );
        // The __Host- prefix (valid with SameSite=None) survives: still no Domain.
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
        assert!(!cookie.contains("Partitioned"), "{cookie}");

        // The clear MUST mirror the shape the cookie was SET with, attribute for
        // attribute, or it names a different jar and the partitioned cookie survives
        // the logout.
        let partitioned = clear_set_cookie(true);
        assert!(partitioned.starts_with("__Host-ironauth_session=; "));
        for attr in [
            "Path=/",
            "Secure",
            "HttpOnly",
            "SameSite=None",
            "Partitioned",
            "Max-Age=0",
        ] {
            assert!(partitioned.contains(attr), "missing {attr}: {partitioned}");
        }
        assert!(!partitioned.contains("Domain"), "{partitioned}");
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
    fn op_browser_state_cookie_is_script_readable_cross_site_and_unprefixed() {
        // Issue #39: the OP browser-state cookie is the deliberate OPPOSITE of the
        // session cookie on three axes, so the check_session_iframe can read it from a
        // third-party context. Its value is the one-way op_browser_state digest, so a
        // script-readable, cross-site cookie leaks nothing.
        let cookie = build_op_browser_state_cookie("opbsdigest", Duration::from_secs(3600));
        assert!(cookie.starts_with("__ironauth_opbs=opbsdigest; "));
        for attr in ["Path=/", "Secure", "SameSite=None", "Max-Age=3600"] {
            assert!(cookie.contains(attr), "missing {attr}: {cookie}");
        }
        // NOT HttpOnly: the iframe reads it via document.cookie.
        assert!(
            !cookie.contains("HttpOnly"),
            "the iframe must be able to read it: {cookie}"
        );
        // NOT __Host- prefixed, and never scoped to a Domain.
        assert!(!cookie.contains("__Host-"), "{cookie}");
        assert!(!cookie.contains("Domain"), "{cookie}");
        // SameSite=None is load-bearing: a Lax cookie is withheld from the third-party
        // iframe, so the mechanism would stay inert.
        assert!(!cookie.contains("SameSite=Lax"), "{cookie}");
    }

    #[test]
    fn clear_op_browser_state_cookie_expires_immediately_with_a_matching_shape() {
        // Logout (issue #39) clears the cookie with Max-Age=0 and an empty value, naming
        // the SAME Path/Secure/SameSite attributes so it targets the same jar and the
        // iframe flips to `changed`.
        let cookie = clear_op_browser_state_cookie();
        assert!(cookie.starts_with("__ironauth_opbs=; "));
        for attr in ["Path=/", "Secure", "SameSite=None", "Max-Age=0"] {
            assert!(cookie.contains(attr), "missing {attr}: {cookie}");
        }
        assert!(!cookie.contains("HttpOnly"), "{cookie}");
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
