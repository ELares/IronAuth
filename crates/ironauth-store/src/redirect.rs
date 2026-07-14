// SPDX-License-Identifier: MIT OR Apache-2.0

//! The redirect-URI registrability rule and the exact-string comparator (issue
//! #13).
//!
//! These two pure functions are the whole redirect-matching policy, and they are
//! security critical: a single accepted bypass here is an open redirector that
//! leaks an authorization code or an error to an attacker-chosen URI (RFC 6749
//! 4.1.2.1, RFC 9700 2.1). They live in the store because the store owns the
//! client registry and thus the registered set the comparator checks against; the
//! OIDC authorization and token endpoints call them.
//!
//! # The comparator is EXACT STRING, with one deviation
//!
//! [`redirect_uri_matches`] compares a registered value against a presented value
//! by EXACT BYTE STRING. There is no wildcard, no substring or prefix, no
//! case-folding, and no path/percent normalization: `https://a/cb` does not match
//! `https://a/cb/`, `HTTPS://a/cb`, `https://a/cb?x`, `https://a/%2e%2e/cb`, or a
//! Unicode look-alike authority. The ONLY deviation is the RFC 8252 section 7.3
//! loopback exception: a native app on a loopback interface cannot fix its
//! callback port, so a registered loopback IP-literal redirect matches a presented
//! one that differs ONLY in the port. That exception is scoped as tightly as
//! possible: it applies only to `http` on the IP LITERALS `127.0.0.1` and `[::1]`
//! (never `localhost`, whose name resolution an attacker can influence), the host
//! literal must be identical, and everything after the authority (path and query)
//! must be byte-identical.
//!
//! # Registrability classifies the RFC 8252 redirect types
//!
//! [`redirect_uri_is_registrable`] accepts exactly the three redirect shapes RFC
//! 8252 defines, and rejects everything else (so a malformed scheme is refused
//! both at registration and at authorization time):
//!
//! - a claimed `https` URL with a non-empty authority (section 7.2),
//! - an `http` loopback IP-literal URL (`127.0.0.1` or `[::1]`, section 7.3),
//! - a private-use (custom) scheme in reverse-domain form, e.g.
//!   `com.example.app:/oauth2redirect` (section 7.1): the scheme must contain a
//!   dot, so a bare single-label scheme like `myapp:` (which a second app could
//!   claim) and the dangerous `javascript:` / `data:` schemes are refused.
//!
//! Every accepted value is also constrained to printable ASCII with no fragment,
//! so a redirect target can never smuggle a header-splitting `\r\n`, hide raw
//! whitespace, carry a `#` fragment, or use a non-ASCII look-alike authority.

/// Whether `uri` is a registrable redirect target under RFC 8252.
///
/// This is the SAME rule at registration time (the client registry refuses to
/// store a value that fails it) and at authorization time (the authorization
/// endpoint refuses to act on a presented value that fails it). Returns `true`
/// only for a claimed `https` URL, an `http` loopback IP-literal URL, or a
/// reverse-domain private-use scheme, each constrained to printable ASCII with no
/// fragment.
#[must_use]
pub fn redirect_uri_is_registrable(uri: &str) -> bool {
    // Safety envelope shared by every accepted shape: non-empty, printable ASCII
    // only (rejecting control characters incl. CR/LF, raw spaces, DEL, and every
    // non-ASCII byte), and no fragment. A conformant redirect URI is already
    // percent-encoded, so nothing legitimate is excluded.
    if uri.is_empty() {
        return false;
    }
    if !uri.bytes().all(|byte| (0x21..=0x7E).contains(&byte)) {
        return false;
    }
    if uri.contains('#') {
        return false;
    }

    let Some((scheme, rest)) = split_scheme(uri) else {
        return false;
    };
    let scheme_lower = scheme.to_ascii_lowercase();
    match scheme_lower.as_str() {
        // A claimed https URL: any non-empty authority that carries NO userinfo. A
        // `user@host` authority is a host-confusion vector (`https://good@evil/cb`
        // targets `evil`, not `good`), so it is refused at registration rather than
        // stored and matched byte-for-byte later.
        "https" => hier_authority(rest)
            .is_some_and(|authority| !authority.is_empty() && !authority.contains('@')),
        // http is permitted ONLY for a loopback IP literal (never a remote host,
        // never localhost).
        "http" => hier_authority(rest).is_some_and(loopback_ip_literal_authority),
        // A private-use (custom) scheme: reverse-domain form (must contain a dot).
        // `rest` is the scheme-specific part (a path); it needs no authority.
        _ => is_reverse_domain_scheme(&scheme_lower),
    }
}

/// Whether a `presented` redirect URI matches a `registered` one.
///
/// EXACT byte-string comparison, with the single RFC 8252 section 7.3 loopback
/// deviation (a variable port on an `http` loopback IP-literal URI). The caller
/// checks a presented value against every registered value and accepts iff one
/// matches. Both arguments are expected to already be registrable (the registered
/// value was validated when stored; the presented value is validated separately),
/// but this function is safe on any input.
#[must_use]
pub fn redirect_uri_matches(registered: &str, presented: &str) -> bool {
    // The default and the only match for anything that is not an http loopback
    // IP-literal URI: an exact byte-for-byte string.
    if registered == presented {
        return true;
    }
    loopback_port_variant_matches(registered, presented)
}

/// Split an absolute URI into its lowercase-comparable scheme and the remainder
/// after the `:`. Returns `None` if the scheme is empty or is not a valid RFC 3986
/// scheme (ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )).
fn split_scheme(uri: &str) -> Option<(&str, &str)> {
    let colon = uri.find(':')?;
    let scheme = &uri[..colon];
    if !is_valid_scheme(scheme) {
        return None;
    }
    Some((scheme, &uri[colon + 1..]))
}

/// Whether `scheme` is a syntactically valid RFC 3986 scheme.
fn is_valid_scheme(scheme: &str) -> bool {
    let mut chars = scheme.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// The authority of a `//authority/...` hierarchical part (the text after the
/// scheme's `:`). The authority runs from just after `//` to the first `/`, `?`,
/// or end. Returns `None` when there is no `//` (so a non-hierarchical scheme has
/// no authority).
fn hier_authority(rest: &str) -> Option<&str> {
    let after = rest.strip_prefix("//")?;
    let end = after.find(['/', '?']).unwrap_or(after.len());
    Some(&after[..end])
}

/// Whether `scheme` is a reverse-domain private-use scheme: it contains at least
/// one dot and has no empty label (no leading/trailing dot, no `..`). `scheme` is
/// already known to be a valid RFC 3986 scheme.
fn is_reverse_domain_scheme(scheme: &str) -> bool {
    if !scheme.contains('.') {
        return false;
    }
    scheme.split('.').all(|label| !label.is_empty())
}

/// Whether an authority is a loopback IP LITERAL, optionally with a valid port:
/// `127.0.0.1[:port]` or `[::1][:port]`. Never `localhost`, never a host that
/// merely starts with a loopback literal, and never one carrying userinfo.
fn loopback_ip_literal_authority(authority: &str) -> bool {
    loopback_host_and_port(authority).is_some()
}

/// Split a loopback authority into its host literal and optional port, or `None`
/// if the host is not exactly `127.0.0.1` or `[::1]`, carries userinfo, or has a
/// malformed port. The returned host is the canonical literal (`127.0.0.1` or
/// `::1`) so two authorities can be compared by host without the IPv6 brackets.
/// `port` is `""` when absent.
fn loopback_host_and_port(authority: &str) -> Option<(&'static str, &str)> {
    // Userinfo (`user@host`) would move the real host past an `@`; a loopback
    // redirect never carries it, so its presence disqualifies the authority.
    if authority.contains('@') {
        return None;
    }
    let (host, port) = split_loopback_host_and_port(authority)?;
    if port_is_valid(port) {
        Some((host, port))
    } else {
        None
    }
}

/// Split a loopback authority into `(canonical host literal, port)` without
/// validating the port, or `None` if the host is not exactly `127.0.0.1` or
/// `[::1]`. `port` is `""` when absent.
fn split_loopback_host_and_port(authority: &str) -> Option<(&'static str, &str)> {
    if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 literal: `[host]` optionally followed by `:port`.
        let close = rest.find(']')?;
        let host = &rest[..close];
        if host != "::1" {
            return None;
        }
        let after = &rest[close + 1..];
        let port = match after.strip_prefix(':') {
            Some(port) => port,
            None if after.is_empty() => "",
            None => return None,
        };
        return Some(("::1", port));
    }
    // IPv4 literal: `host` optionally followed by `:port`.
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, port),
        None => (authority, ""),
    };
    if host != "127.0.0.1" {
        return None;
    }
    Some(("127.0.0.1", port))
}

/// Whether an authority port component is absent (`""`) or a valid TCP port
/// (`1..=65535`). The value must parse as a `u16` and be non-zero, so a numeric
/// but out-of-range authority like `:99999` or `:0` is not treated as a loopback
/// port variant.
fn port_is_valid(port: &str) -> bool {
    if port.is_empty() {
        return true;
    }
    // A leading `+`/`-`/whitespace is rejected by `u16::from_str`, and `0` is not a
    // usable listening port, so require a non-zero in-range value.
    port.parse::<u16>().is_ok_and(|value| value != 0)
}

/// The loopback deviation of [`redirect_uri_matches`]: `true` iff both URIs are
/// `http` loopback IP-literal URIs that are identical in every component except
/// the port. The scheme is matched case-insensitively (RFC 3986 schemes are
/// case-insensitive); the host literal and everything after the authority (path
/// and query) are matched EXACTLY.
fn loopback_port_variant_matches(registered: &str, presented: &str) -> bool {
    let (Some(reg_rest), Some(pre_rest)) = (
        strip_http_scheme_ci(registered),
        strip_http_scheme_ci(presented),
    ) else {
        return false;
    };
    let (reg_authority, reg_tail) = split_authority_and_tail(reg_rest);
    let (pre_authority, pre_tail) = split_authority_and_tail(pre_rest);

    // The path and query after the authority must be byte-identical: only the port
    // may vary.
    if reg_tail != pre_tail {
        return false;
    }
    let (Some((reg_host, _)), Some((pre_host, _))) = (
        loopback_host_and_port(reg_authority),
        loopback_host_and_port(pre_authority),
    ) else {
        return false;
    };
    // The loopback literal itself must match (127.0.0.1 vs 127.0.0.1, ::1 vs ::1),
    // so a v4 registration is not satisfied by a v6 presentation.
    reg_host == pre_host
}

/// Strip a case-insensitive `http://` prefix, or `None` if the URI is not http.
fn strip_http_scheme_ci(uri: &str) -> Option<&str> {
    const PREFIX: &str = "http://";
    if uri.len() >= PREFIX.len() && uri[..PREFIX.len()].eq_ignore_ascii_case(PREFIX) {
        Some(&uri[PREFIX.len()..])
    } else {
        None
    }
}

/// Split the text after `http://` into its authority (up to the first `/` or `?`)
/// and the tail (the delimiter and everything after it, or `""`).
fn split_authority_and_tail(rest: &str) -> (&str, &str) {
    match rest.find(['/', '?']) {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------
    // The registrability rule.
    // ---------------------------------------------------------------------

    #[test]
    fn accepts_the_three_rfc8252_redirect_shapes() {
        // Claimed https.
        assert!(redirect_uri_is_registrable("https://client.example/cb"));
        assert!(redirect_uri_is_registrable(
            "https://client.example:8443/cb?x=1"
        ));
        // http loopback IP literals (never localhost).
        assert!(redirect_uri_is_registrable("http://127.0.0.1/cb"));
        assert!(redirect_uri_is_registrable("http://127.0.0.1:52000/cb"));
        assert!(redirect_uri_is_registrable("http://[::1]/cb"));
        assert!(redirect_uri_is_registrable("http://[::1]:9000/cb"));
        // Private-use reverse-domain scheme.
        assert!(redirect_uri_is_registrable(
            "com.example.app:/oauth2redirect"
        ));
        assert!(redirect_uri_is_registrable("com.example.app:/cb?code=1"));
    }

    #[test]
    fn rejects_non_loopback_http_and_localhost() {
        // Plain http to a remote host is not a registrable redirect (OAuth 2.1).
        assert!(!redirect_uri_is_registrable("http://client.example/cb"));
        // localhost is a NAME, not a loopback IP literal: refused (its resolution
        // can be influenced).
        assert!(!redirect_uri_is_registrable("http://localhost/cb"));
        assert!(!redirect_uri_is_registrable("http://localhost:8080/cb"));
    }

    #[test]
    fn rejects_dangerous_and_bare_schemes() {
        // No dot in the scheme => not reverse-domain => refused. This catches the
        // dangerous known schemes and a bare single-label custom scheme.
        assert!(!redirect_uri_is_registrable("javascript:alert(1)"));
        assert!(!redirect_uri_is_registrable("data:text/html,evil"));
        assert!(!redirect_uri_is_registrable("myapp:/cb"));
        assert!(!redirect_uri_is_registrable("file:/etc/passwd"));
        // ftp is neither https, http-loopback, nor reverse-domain.
        assert!(!redirect_uri_is_registrable("ftp://host/cb"));
    }

    #[test]
    fn rejects_unsafe_bytes_fragments_and_malformed() {
        assert!(!redirect_uri_is_registrable(""));
        // A raw space, a tab, and CR/LF (header splitting) are all refused.
        assert!(!redirect_uri_is_registrable("https://client.example/a b"));
        assert!(!redirect_uri_is_registrable("https://client.example/a\tb"));
        assert!(!redirect_uri_is_registrable(
            "https://client.example/cb\r\nSet-Cookie: x=y"
        ));
        // A fragment is never allowed on a redirect target.
        assert!(!redirect_uri_is_registrable(
            "https://client.example/cb#frag"
        ));
        // A non-ASCII (Unicode look-alike) authority is refused.
        assert!(!redirect_uri_is_registrable(
            "https://client\u{0430}.example/cb"
        ));
        // Relative and empty-authority forms.
        assert!(!redirect_uri_is_registrable("/relative/path"));
        assert!(!redirect_uri_is_registrable("https:///no-host"));
        // A scheme with an empty label is not a valid reverse-domain scheme.
        assert!(!redirect_uri_is_registrable("com..app:/cb"));
        assert!(!redirect_uri_is_registrable(".com.app:/cb"));
    }

    #[test]
    fn rejects_userinfo_in_a_registrable_https_uri() {
        // A `user@host` authority is refused at registration: the effective host is
        // what follows the `@`, so storing one would enshrine a host-confusion
        // ambiguity even though the later match is byte-exact.
        assert!(!redirect_uri_is_registrable(
            "https://client.example@evil.example/cb"
        ));
        assert!(!redirect_uri_is_registrable(
            "https://user:pass@client.example/cb"
        ));
        assert!(!redirect_uri_is_registrable("https://@client.example/cb"));
        // The benign form (no userinfo) still registers.
        assert!(redirect_uri_is_registrable("https://client.example/cb"));
    }

    #[test]
    fn loopback_port_variant_rejects_an_out_of_range_port() {
        // The loopback exception varies ONLY a valid TCP port. A numeric but
        // out-of-range or zero port is not a port, so it does not match.
        let reg = "http://127.0.0.1:8080/cb";
        assert!(redirect_uri_matches(reg, "http://127.0.0.1:52000/cb"));
        assert!(!redirect_uri_matches(reg, "http://127.0.0.1:99999/cb"));
        assert!(!redirect_uri_matches(reg, "http://127.0.0.1:0/cb"));
        assert!(!redirect_uri_matches(reg, "http://127.0.0.1:65536/cb"));
        // 65535 is the max valid port and still matches as a variant.
        assert!(redirect_uri_matches(reg, "http://127.0.0.1:65535/cb"));
    }

    // ---------------------------------------------------------------------
    // The exact-string comparator and the CVE regression corpus. Every entry is
    // a bypass class that MUST stay rejected (zero accepted bypasses).
    // ---------------------------------------------------------------------

    #[test]
    fn exact_match_accepts_only_the_identical_string() {
        let reg = "https://client.example/cb";
        assert!(redirect_uri_matches(reg, "https://client.example/cb"));
        assert!(!redirect_uri_matches(reg, "https://client.example/cb "));
    }

    #[test]
    fn cve_corpus_no_accepted_bypasses() {
        // The registered value under attack.
        let reg = "https://client.example/cb";
        // Each presented value below is a classic redirect-bypass technique. NONE
        // may match the exact registered string.
        let bypasses = [
            // Wildcard / open-ended.
            "https://client.example/cb/*",
            "https://client.example/*",
            "https://*.example/cb",
            // Substring / prefix / suffix.
            "https://client.example/cb/extra",
            "https://client.example/cbextra",
            "https://client.example/c",
            "https://evil.example/https://client.example/cb",
            // Trailing slash and query drift.
            "https://client.example/cb/",
            "https://client.example/cb?x=1",
            "https://client.example/cb#x",
            // Case folding.
            "https://CLIENT.example/cb",
            "HTTPS://client.example/cb",
            "https://client.example/CB",
            // Host confusion: userinfo, added port, subdomain, sibling domain.
            "https://client.example@evil.example/cb",
            "https://client.example:443/cb",
            "https://client.example.evil.example/cb",
            "https://evil.example/cb",
            "https://client.example.evil/cb",
            // Backslash and double-slash tricks.
            "https://client.example\\@evil.example/cb",
            "https://client.example//cb",
            // Encoded traversal and dot-segments.
            "https://client.example/%2e%2e/cb",
            "https://client.example/../cb",
            "https://client.example/./cb",
            "https://client.example/foo/../cb",
            // Percent-encoded look-alikes of the whole string.
            "https://client.example/cb%00",
            "https://client.example/cb%20",
            // Unicode / IDN homograph authority (also rejected as non-ASCII).
            "https://client\u{0435}xample/cb",
            "https://xn--clientexample/cb",
            // Scheme downgrade / swap.
            "http://client.example/cb",
            "javascript://client.example/cb",
            // Whitespace injection.
            "https://client.example/cb\t",
            "https://client.example /cb",
        ];
        for presented in bypasses {
            assert!(
                !redirect_uri_matches(reg, presented),
                "redirect bypass accepted: registered={reg:?} presented={presented:?}"
            );
        }
    }

    // ---------------------------------------------------------------------
    // The loopback port exception, scoped as tightly as possible.
    // ---------------------------------------------------------------------

    #[test]
    fn loopback_ip_literal_allows_only_a_variable_port() {
        // A registered loopback IP literal matches a presented one that differs
        // ONLY in the port (RFC 8252 7.3), for both v4 and v6.
        assert!(redirect_uri_matches(
            "http://127.0.0.1/cb",
            "http://127.0.0.1:54213/cb"
        ));
        assert!(redirect_uri_matches(
            "http://127.0.0.1:8080/cb",
            "http://127.0.0.1:9090/cb"
        ));
        assert!(redirect_uri_matches(
            "http://[::1]/cb",
            "http://[::1]:41000/cb"
        ));
        // The path and query must still be byte-identical: only the port varies.
        assert!(!redirect_uri_matches(
            "http://127.0.0.1/cb",
            "http://127.0.0.1:9000/other"
        ));
        assert!(!redirect_uri_matches(
            "http://127.0.0.1/cb",
            "http://127.0.0.1:9000/cb?x=1"
        ));
    }

    #[test]
    fn loopback_exception_never_bridges_host_or_scheme() {
        // The exception is loopback-only: a non-loopback host gets strict exact
        // match, so a variable port never bridges two different ports there.
        assert!(!redirect_uri_matches(
            "https://client.example/cb",
            "https://client.example:8443/cb"
        ));
        assert!(!redirect_uri_matches(
            "http://client.example/cb",
            "http://client.example:8080/cb"
        ));
        // v4 and v6 loopback literals are distinct; one does not satisfy the other.
        assert!(!redirect_uri_matches(
            "http://127.0.0.1/cb",
            "http://[::1]:9/cb"
        ));
        // A host that merely starts with the loopback literal is not loopback.
        assert!(!redirect_uri_matches(
            "http://127.0.0.1/cb",
            "http://127.0.0.1.evil.example:9/cb"
        ));
        // Userinfo smuggling a different real host is rejected.
        assert!(!redirect_uri_matches(
            "http://127.0.0.1/cb",
            "http://127.0.0.1:9@evil.example/cb"
        ));
        // localhost is not an IP literal, so the port exception never applies.
        assert!(!redirect_uri_matches(
            "http://localhost/cb",
            "http://localhost:9000/cb"
        ));
    }

    #[test]
    fn identical_loopback_matches_by_the_exact_path() {
        // An identical loopback URL still matches (the exact-string path), and a
        // different path never does even on loopback.
        assert!(redirect_uri_matches(
            "http://127.0.0.1:9000/cb",
            "http://127.0.0.1:9000/cb"
        ));
        assert!(!redirect_uri_matches(
            "http://127.0.0.1:9000/cb",
            "http://127.0.0.1:9000/cb/evil"
        ));
    }
}
