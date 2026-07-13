// SPDX-License-Identifier: MIT OR Apache-2.0

//! The trusted-proxy policy: how the effective client IP, scheme, and host are
//! decided for a request.
//!
//! Forwarded-header trust is a documented account-takeover class (a forged
//! `Forwarded` or `X-Forwarded-Proto` that a server believes can move the
//! issuer, defeat an IP allowlist, or bypass mTLS). The policy here is
//! deliberately strict and fails closed:
//!
//! - Scheme, host, and the issuer/base-URL always derive from
//!   `server.public_url` config. No request header (`Host`, `X-Forwarded-*`,
//!   `Forwarded`) can move them. See [`SiteContext`].
//! - The effective client IP is the transport peer unless the operator has
//!   explicitly declared a trusted-proxy topology (`proxy.trust_forwarded =
//!   true` AND `proxy.trusted_hops = N > 0`). Even then the request must
//!   present exactly `N` forwarding entries; any other count, a malformed
//!   `Forwarded`, or both `Forwarded` and `X-Forwarded-For` present at once is
//!   ambiguous and fails closed to the peer (with a counter incremented by the
//!   caller). See [`ProxyPolicy::resolve_client_ip`].
//!
//! The core decision is a pure function over `(peer, headers)` so the
//! adversarial suite can assert it directly, independent of any socket.

use std::net::{IpAddr, Ipv6Addr};

use http::HeaderMap;
use ironauth_config::{ProxyConfig, ServerConfig};

use crate::error::ServerError;

/// The config-derived scheme and host for this deployment. Everything that
/// leaves the process as an absolute URL (issuer, endpoint URLs, redirect
/// validation base) is built from this, never from a request header.
#[derive(Debug, Clone)]
pub struct SiteContext {
    scheme: String,
    authority: String,
}

impl SiteContext {
    /// Derive the site context from `server.public_url`, falling back to the
    /// bind address for single-host development when `public_url` is unset.
    ///
    /// # Errors
    ///
    /// [`ServerError::InvalidPublicUrl`] if `public_url` is set but is not an
    /// `http`/`https` URL with an authority.
    pub fn derive(server: &ServerConfig) -> Result<Self, ServerError> {
        match server.public_url.as_deref() {
            Some(url) => Self::from_public_url(url),
            None => Ok(Self {
                // Dev fallback: plaintext behind the bind address. Production
                // deployments set public_url and terminate TLS at the proxy.
                scheme: "http".to_owned(),
                authority: server.bind.clone(),
            }),
        }
    }

    /// Parse an explicit `public_url` into scheme and authority.
    fn from_public_url(url: &str) -> Result<Self, ServerError> {
        let (scheme, rest) =
            url.split_once("://")
                .ok_or_else(|| ServerError::InvalidPublicUrl {
                    reason: "expected scheme://host (no '://' found)".to_owned(),
                })?;
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return Err(ServerError::InvalidPublicUrl {
                reason: format!("scheme must be http or https, found '{scheme}'"),
            });
        }
        // Authority is everything up to the first path/query/fragment
        // separator. A trailing path is accepted but ignored: the base URL is
        // scheme + authority only.
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        if authority.is_empty() {
            return Err(ServerError::InvalidPublicUrl {
                reason: "missing host".to_owned(),
            });
        }
        Ok(Self {
            scheme,
            authority: authority.to_owned(),
        })
    }

    /// The config-derived scheme (`http` or `https`).
    #[must_use]
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// The config-derived authority (`host[:port]`).
    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// The config-derived base URL (`scheme://authority`), the root every
    /// issuer and endpoint URL is built from.
    #[must_use]
    pub fn base_url(&self) -> String {
        format!("{}://{}", self.scheme, self.authority)
    }
}

/// The effective per-request context after the trusted-proxy policy ran.
///
/// `scheme` and `host` are always config-derived (from [`SiteContext`]), never
/// read from a request header; only `client_ip` reflects forwarding, and only
/// when the policy honored it. Downstream handlers extract this from request
/// extensions.
#[derive(Debug, Clone)]
pub struct ClientContext {
    /// The effective client IP (a forwarded address only when the decision was
    /// [`ForwardDecision::Honored`]; otherwise the transport peer).
    pub client_ip: IpAddr,
    /// The config-derived scheme (`http` or `https`).
    pub scheme: String,
    /// The config-derived authority (`host[:port]`).
    pub host: String,
    /// How the client IP was decided.
    pub forward_decision: ForwardDecision,
}

/// The evaluated trusted-proxy policy.
#[derive(Debug, Clone, Copy)]
pub struct ProxyPolicy {
    trusted_hops: u32,
    trust_forwarded: bool,
}

impl ProxyPolicy {
    /// Build the policy from config.
    #[must_use]
    pub fn from_config(proxy: &ProxyConfig) -> Self {
        Self {
            trusted_hops: proxy.trusted_hops,
            trust_forwarded: proxy.trust_forwarded,
        }
    }

    /// Whether the policy consults forwarding headers at all.
    #[must_use]
    pub fn honors_forwarding(&self) -> bool {
        self.trust_forwarded && self.trusted_hops > 0
    }

    /// Decide the effective client IP for a request that arrived from
    /// transport `peer` carrying `headers`.
    ///
    /// The result is always safe to use: on any ambiguity it is `peer` and the
    /// decision records why, so the caller increments the fail-closed counter.
    #[must_use]
    pub fn resolve_client_ip(&self, peer: IpAddr, headers: &HeaderMap) -> ClientResolution {
        if !self.honors_forwarding() {
            return ClientResolution {
                client_ip: peer,
                decision: ForwardDecision::Direct,
            };
        }
        let fail = |reason| ClientResolution {
            client_ip: peer,
            decision: ForwardDecision::FailedClosed(reason),
        };
        let entries = match collect_forwarding_entries(headers) {
            Ok(entries) => entries,
            Err(reason) => return fail(reason),
        };
        // The topology is fixed: exactly `trusted_hops` proxies each append one
        // entry, so the count must match exactly. Any other count means an
        // untrusted party injected entries, a proxy is missing, or the request
        // bypassed the chain: all ambiguous, all fail closed.
        let expected = self.trusted_hops as usize;
        if entries.len() != expected {
            return fail(FailClosedReason::HopCountMismatch {
                expected,
                found: entries.len(),
            });
        }
        // With exactly the expected entries, the leftmost is the real client:
        // each proxy prepends nothing and appends the host that connected to
        // it, so entry 0 is the origin.
        ClientResolution {
            client_ip: entries[0],
            decision: ForwardDecision::Honored,
        }
    }
}

/// The outcome of a client-IP decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientResolution {
    /// The effective client IP: an extracted forwarded address only when
    /// [`ForwardDecision::Honored`]; otherwise the transport peer.
    pub client_ip: IpAddr,
    /// How the IP was decided.
    pub decision: ForwardDecision,
}

/// How the effective client IP was decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardDecision {
    /// No trusted-proxy topology is configured; the transport peer is used and
    /// every forwarding header is ignored.
    Direct,
    /// Forwarding was configured and the request matched it exactly; a
    /// forwarded address was honored.
    Honored,
    /// Forwarding was configured but the request was ambiguous; the policy
    /// fell back to the transport peer.
    FailedClosed(FailClosedReason),
}

impl ForwardDecision {
    /// Whether this decision is a fail-closed fallback (the caller increments
    /// the rejection counter on `true`).
    #[must_use]
    pub fn is_failed_closed(&self) -> bool {
        matches!(self, ForwardDecision::FailedClosed(_))
    }
}

/// Why a forwarding decision failed closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailClosedReason {
    /// The number of forwarding entries did not equal `trusted_hops`.
    HopCountMismatch {
        /// The configured trusted-hop count.
        expected: usize,
        /// The number of entries actually presented.
        found: usize,
    },
    /// Both `Forwarded` and `X-Forwarded-For` were present; which to believe
    /// is undefined, so neither is believed.
    ConflictingHeaders,
    /// A forwarding entry was not a parseable IP address (obfuscated node,
    /// `unknown`, or malformed).
    MalformedEntry,
}

/// Collect the forwarding entries from either `Forwarded` or `X-Forwarded-For`.
///
/// Returns the entries left-to-right (origin first). Presence of both header
/// families, or any unparseable entry, is an error and must fail closed.
fn collect_forwarding_entries(headers: &HeaderMap) -> Result<Vec<IpAddr>, FailClosedReason> {
    let has_forwarded = headers.contains_key("forwarded");
    let has_xff = headers.contains_key("x-forwarded-for");
    if has_forwarded && has_xff {
        return Err(FailClosedReason::ConflictingHeaders);
    }
    if has_forwarded {
        return collect_forwarded_rfc7239(headers);
    }
    if has_xff {
        return collect_x_forwarded_for(headers);
    }
    // Neither header present. With forwarding configured this is a hop-count
    // mismatch (zero found), which the caller turns into a fail-closed result.
    Ok(Vec::new())
}

/// Parse `X-Forwarded-For` across every header line, splitting on commas.
fn collect_x_forwarded_for(headers: &HeaderMap) -> Result<Vec<IpAddr>, FailClosedReason> {
    let mut out = Vec::new();
    for value in headers.get_all("x-forwarded-for") {
        let text = value
            .to_str()
            .map_err(|_| FailClosedReason::MalformedEntry)?;
        for token in text.split(',') {
            let token = token.trim();
            if token.is_empty() {
                return Err(FailClosedReason::MalformedEntry);
            }
            out.push(parse_forwarded_node(token).ok_or(FailClosedReason::MalformedEntry)?);
        }
    }
    Ok(out)
}

/// Parse RFC 7239 `Forwarded` across every header line, extracting each
/// element's `for=` node.
fn collect_forwarded_rfc7239(headers: &HeaderMap) -> Result<Vec<IpAddr>, FailClosedReason> {
    let mut out = Vec::new();
    for value in headers.get_all("forwarded") {
        let text = value
            .to_str()
            .map_err(|_| FailClosedReason::MalformedEntry)?;
        for element in text.split(',') {
            let mut node = None;
            for param in element.split(';') {
                let Some((key, val)) = param.split_once('=') else {
                    continue;
                };
                if key.trim().eq_ignore_ascii_case("for") {
                    node = Some(val.trim());
                }
            }
            let node = node.ok_or(FailClosedReason::MalformedEntry)?;
            out.push(parse_forwarded_node(node).ok_or(FailClosedReason::MalformedEntry)?);
        }
    }
    Ok(out)
}

/// Parse one forwarding node into an IP, tolerating quotes, IPv6 brackets, and
/// an optional `:port`. Obfuscated identifiers (`unknown`, `_hidden`) return
/// `None`, which fails the request closed.
fn parse_forwarded_node(raw: &str) -> Option<IpAddr> {
    let s = raw.trim().trim_matches('"').trim();
    if let Some(rest) = s.strip_prefix('[') {
        // [ipv6] or [ipv6]:port
        let end = rest.find(']')?;
        return rest[..end].parse::<Ipv6Addr>().ok().map(IpAddr::V6);
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(ip);
    }
    // Bare ipv4:port (a bare IPv6 has multiple colons and parsed above).
    if let Some((host, port)) = s.rsplit_once(':') {
        if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) {
            return host.parse::<IpAddr>().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderName, HeaderValue};
    use std::net::Ipv4Addr;

    const PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                name.parse::<HeaderName>().expect("valid header name"),
                HeaderValue::from_str(value).expect("valid header"),
            );
        }
        map
    }

    fn zero_trust() -> ProxyPolicy {
        ProxyPolicy::from_config(&ProxyConfig::default())
    }

    fn trust(hops: u32) -> ProxyPolicy {
        ProxyPolicy {
            trusted_hops: hops,
            trust_forwarded: true,
        }
    }

    #[test]
    fn zero_trust_ignores_every_forwarding_header() {
        let policy = zero_trust();
        let hs = headers(&[
            ("x-forwarded-for", "1.2.3.4"),
            ("x-forwarded-proto", "https"),
            ("x-forwarded-host", "evil.example"),
            ("forwarded", "for=9.9.9.9;proto=https"),
        ]);
        let resolved = policy.resolve_client_ip(PEER, &hs);
        assert_eq!(resolved.client_ip, PEER);
        assert_eq!(resolved.decision, ForwardDecision::Direct);
    }

    #[test]
    fn trust_disabled_but_hops_set_still_ignores() {
        let policy = ProxyPolicy {
            trusted_hops: 2,
            trust_forwarded: false,
        };
        let hs = headers(&[("x-forwarded-for", "1.2.3.4, 5.6.7.8")]);
        assert_eq!(
            policy.resolve_client_ip(PEER, &hs).decision,
            ForwardDecision::Direct
        );
    }

    #[test]
    fn one_trusted_hop_honors_the_single_client_entry() {
        let policy = trust(1);
        let hs = headers(&[("x-forwarded-for", "203.0.113.7")]);
        let resolved = policy.resolve_client_ip(PEER, &hs);
        assert_eq!(resolved.decision, ForwardDecision::Honored);
        assert_eq!(
            resolved.client_ip,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))
        );
    }

    #[test]
    fn client_injected_prefix_fails_closed_on_hop_count() {
        // One trusted proxy, so exactly one entry is expected. A client that
        // forges an extra entry produces two, which fails closed to the peer.
        let policy = trust(1);
        let hs = headers(&[("x-forwarded-for", "66.66.66.66, 203.0.113.7")]);
        let resolved = policy.resolve_client_ip(PEER, &hs);
        assert!(resolved.decision.is_failed_closed());
        assert_eq!(resolved.client_ip, PEER);
    }

    #[test]
    fn two_trusted_hops_take_the_leftmost() {
        let policy = trust(2);
        let hs = headers(&[("x-forwarded-for", "203.0.113.7, 198.51.100.2")]);
        let resolved = policy.resolve_client_ip(PEER, &hs);
        assert_eq!(resolved.decision, ForwardDecision::Honored);
        assert_eq!(
            resolved.client_ip,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))
        );
    }

    #[test]
    fn missing_forwarding_header_with_trust_fails_closed() {
        let policy = trust(1);
        let resolved = policy.resolve_client_ip(PEER, &HeaderMap::new());
        assert!(resolved.decision.is_failed_closed());
        assert_eq!(resolved.client_ip, PEER);
    }

    #[test]
    fn both_forwarded_families_present_fails_closed() {
        let policy = trust(1);
        let hs = headers(&[
            ("x-forwarded-for", "203.0.113.7"),
            ("forwarded", "for=203.0.113.7"),
        ]);
        let resolved = policy.resolve_client_ip(PEER, &hs);
        assert_eq!(
            resolved.decision,
            ForwardDecision::FailedClosed(FailClosedReason::ConflictingHeaders)
        );
    }

    #[test]
    fn malformed_and_obfuscated_entries_fail_closed() {
        let policy = trust(1);
        for value in ["unknown", "_hidden", "not-an-ip", ""] {
            let hs = headers(&[("x-forwarded-for", value)]);
            assert!(
                policy
                    .resolve_client_ip(PEER, &hs)
                    .decision
                    .is_failed_closed(),
                "value {value:?} should fail closed"
            );
        }
    }

    #[test]
    fn rfc7239_forwarded_is_parsed_and_honored() {
        let policy = trust(1);
        let hs = headers(&[("forwarded", "for=203.0.113.7;proto=https;host=evil.example")]);
        let resolved = policy.resolve_client_ip(PEER, &hs);
        assert_eq!(resolved.decision, ForwardDecision::Honored);
        assert_eq!(
            resolved.client_ip,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))
        );
    }

    #[test]
    fn rfc7239_ipv6_node_with_brackets_and_port() {
        let policy = trust(1);
        let hs = headers(&[("forwarded", "for=\"[2001:db8::1]:4711\"")]);
        let resolved = policy.resolve_client_ip(PEER, &hs);
        assert_eq!(resolved.decision, ForwardDecision::Honored);
        assert_eq!(resolved.client_ip, "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn ipv4_with_port_parses() {
        assert_eq!(
            parse_forwarded_node("203.0.113.7:5000"),
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)))
        );
    }

    fn server_with_url(url: &str) -> ServerConfig {
        ServerConfig {
            public_url: Some(url.to_owned()),
            ..ServerConfig::default()
        }
    }

    #[test]
    fn site_context_derives_scheme_and_host_from_public_url() {
        let server = server_with_url("https://id.example.com/auth");
        let site = SiteContext::derive(&server).expect("valid url");
        assert_eq!(site.scheme(), "https");
        assert_eq!(site.authority(), "id.example.com");
        assert_eq!(site.base_url(), "https://id.example.com");
    }

    #[test]
    fn site_context_falls_back_to_bind_when_public_url_unset() {
        let server = ServerConfig::default();
        let site = SiteContext::derive(&server).expect("valid");
        assert_eq!(site.scheme(), "http");
        assert_eq!(site.authority(), "127.0.0.1:8443");
    }

    #[test]
    fn site_context_rejects_non_http_scheme_and_missing_host() {
        assert!(SiteContext::derive(&server_with_url("ftp://x")).is_err());
        assert!(SiteContext::derive(&server_with_url("https://")).is_err());
    }
}
