// SPDX-License-Identifier: MIT OR Apache-2.0

//! Parsing an outbound URL into a validated [`Target`], plus the scheme
//! allowlist.
//!
//! Parsing is deliberately strict and total: it accepts only absolute `http`
//! and `https` URLs with a host, rejects embedded userinfo (a credential-in-URL
//! smell that has no place in an outbound OP fetch), and normalizes the host so
//! IPv4/IPv6 literals are recognized up front (they skip DNS and are validated
//! directly). [`parse_target`] is exported so the fuzz target and the stable
//! adversarial table drive the exact parser the connector uses.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

/// The scheme of a parsed target. Only these two are representable; every other
/// scheme is rejected at parse time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// TLS-protected HTTP. The default and only scheme allowed unless the caller
    /// explicitly opts into plaintext.
    Https,
    /// Plaintext HTTP. Permitted only when the request opts in; the seam exists
    /// so later non-production guardrails can gate it.
    Http,
}

impl Scheme {
    /// The default destination port for the scheme.
    #[must_use]
    pub const fn default_port(self) -> u16 {
        match self {
            Scheme::Https => 443,
            Scheme::Http => 80,
        }
    }

    /// The scheme keyword.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Scheme::Https => "https",
            Scheme::Http => "http",
        }
    }
}

/// A validated outbound target: scheme, host, port, and origin-form request
/// path. A host that is an IP literal is recognized as [`Target::literal_ip`]
/// so the connector validates it directly instead of resolving it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// The scheme (`https` or `http`).
    pub scheme: Scheme,
    /// The host, with any IPv6 brackets stripped.
    pub host: String,
    /// The destination port (explicit, or the scheme default).
    pub port: u16,
    /// The origin-form path and query to put on the request line (always begins
    /// with `/`).
    pub path_and_query: String,
    /// `Some` when the host is an IP literal, so DNS resolution is skipped and
    /// the address is validated directly.
    pub literal_ip: Option<IpAddr>,
}

impl Target {
    /// The value for the `Host` request header: the host (IPv6 bracketed) plus
    /// the port when it is not the scheme default. This is sent verbatim so the
    /// origin sees the name the caller asked for, even though the socket is
    /// pinned to a validated IP.
    #[must_use]
    pub fn host_header(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == self.scheme.default_port() {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

/// Why a URL could not be turned into a [`Target`]. Every variant is a
/// caller-side malformed-input condition (not a network or topology signal), so
/// surfacing the distinction leaks no SSRF oracle.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TargetError {
    /// The string is not a valid absolute URI.
    Malformed,
    /// The scheme is missing or is neither `http` nor `https`.
    UnsupportedScheme,
    /// The URI has no host component.
    MissingHost,
    /// The authority carries userinfo (`user:pass@host`), which is refused so no
    /// credential rides in the URL.
    UserinfoPresent,
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            TargetError::Malformed => "not a valid absolute URL",
            TargetError::UnsupportedScheme => "scheme must be http or https",
            TargetError::MissingHost => "URL has no host",
            TargetError::UserinfoPresent => "URL must not contain userinfo",
        };
        f.write_str(message)
    }
}

impl std::error::Error for TargetError {}

/// Parse an outbound URL into a validated [`Target`].
///
/// # Errors
///
/// Returns a [`TargetError`] if the string is not an absolute `http`/`https`
/// URL with a host and no userinfo. This function never resolves DNS or touches
/// the network; it is a pure syntactic gate.
pub fn parse_target(url: &str) -> Result<Target, TargetError> {
    let uri = http::Uri::from_str(url).map_err(|_| TargetError::Malformed)?;

    let scheme = match uri.scheme_str() {
        Some("https") => Scheme::Https,
        Some("http") => Scheme::Http,
        _ => return Err(TargetError::UnsupportedScheme),
    };

    let authority = uri.authority().ok_or(TargetError::MissingHost)?;
    // `http::Authority` keeps userinfo in its string form even though it exposes
    // no accessor for it; an `@` in the authority is userinfo we refuse.
    if authority.as_str().contains('@') {
        return Err(TargetError::UserinfoPresent);
    }

    let raw_host = uri.host().ok_or(TargetError::MissingHost)?;
    if raw_host.is_empty() {
        return Err(TargetError::MissingHost);
    }
    // Strip IPv6 literal brackets, if present, before classifying the host.
    let host = raw_host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(raw_host);
    if host.is_empty() {
        return Err(TargetError::MissingHost);
    }

    let literal_ip = IpAddr::from_str(host).ok();
    let port = uri.port_u16().unwrap_or_else(|| scheme.default_port());

    let path_and_query = match uri.path_and_query() {
        Some(pq) if !pq.as_str().is_empty() => {
            let text = pq.as_str();
            if text.starts_with('/') {
                text.to_owned()
            } else {
                format!("/{text}")
            }
        }
        _ => "/".to_owned(),
    };

    Ok(Target {
        scheme,
        host: host.to_owned(),
        port,
        path_and_query,
        literal_ip,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_https_with_default_port() {
        let target = parse_target("https://example.com/.well-known/jwks.json").expect("valid");
        assert_eq!(target.scheme, Scheme::Https);
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 443);
        assert_eq!(target.path_and_query, "/.well-known/jwks.json");
        assert_eq!(target.literal_ip, None);
        assert_eq!(target.host_header(), "example.com");
    }

    #[test]
    fn preserves_query_and_explicit_port() {
        let target = parse_target("https://example.com:8443/a?b=c&d=e").expect("valid");
        assert_eq!(target.port, 8443);
        assert_eq!(target.path_and_query, "/a?b=c&d=e");
        assert_eq!(target.host_header(), "example.com:8443");
    }

    #[test]
    fn empty_path_normalizes_to_slash() {
        let target = parse_target("https://example.com").expect("valid");
        assert_eq!(target.path_and_query, "/");
    }

    #[test]
    fn recognizes_ipv4_and_ipv6_literals() {
        let v4 = parse_target("http://169.254.169.254/latest/meta-data/").expect("valid");
        assert_eq!(v4.literal_ip, Some("169.254.169.254".parse().unwrap()));
        assert_eq!(v4.scheme, Scheme::Http);

        let v6 = parse_target("https://[::1]:9000/x").expect("valid");
        assert_eq!(v6.host, "::1");
        assert_eq!(v6.literal_ip, Some("::1".parse().unwrap()));
        assert_eq!(v6.port, 9000);
        assert_eq!(v6.host_header(), "[::1]:9000");
    }

    #[test]
    fn rejects_unsupported_schemes() {
        // Schemes with an authority reach the scheme check and are named
        // unsupported; opaque-form schemes the URI parser rejects outright are
        // still rejected (as malformed). Either way, only http/https survive.
        assert_eq!(
            parse_target("ftp://example.com/"),
            Err(TargetError::UnsupportedScheme)
        );
        assert_eq!(
            parse_target("gopher://example.com/"),
            Err(TargetError::UnsupportedScheme)
        );
        assert_eq!(
            parse_target("javascript:alert(1)"),
            Err(TargetError::UnsupportedScheme)
        );
        for url in ["file:///etc/passwd", "data:text/plain,hi"] {
            assert!(parse_target(url).is_err(), "{url} must be rejected");
        }
    }

    #[test]
    fn rejects_userinfo() {
        assert_eq!(
            parse_target("https://user:pass@example.com/"),
            Err(TargetError::UserinfoPresent)
        );
        assert_eq!(
            parse_target("https://admin@169.254.169.254/"),
            Err(TargetError::UserinfoPresent)
        );
    }

    #[test]
    fn rejects_schemeless_and_empty_inputs() {
        // A bare authority with no scheme, an empty string, and a scheme with no
        // usable authority are all rejected; none reaches the network.
        for url in [
            "example.com/path",
            "",
            "https://",
            "https:///path",
            "not a url",
        ] {
            assert!(parse_target(url).is_err(), "{url} must be rejected");
        }
    }
}
