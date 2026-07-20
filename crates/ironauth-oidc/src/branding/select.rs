// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-domain / per-client brand SELECTION (issue #86, PR 3): the pure precedence a scope's
//! installed brands are resolved by for one request.
//!
//! The precedence is per-CLIENT > per-DOMAIN > env-DEFAULT > NEUTRAL:
//!
//! 1. a brand whose `client_id` equals the authorize request's `client_id` wins (the most
//!    specific selection: a named relying party gets its own brand);
//! 2. else a brand whose `host_pattern` matches the request Host wins (a per-domain brand);
//! 3. else the environment DEFAULT brand (`is_default`);
//! 4. else NONE, so the render path uses the #85 neutral default (byte-identical to an
//!    unbranded environment).
//!
//! Host matching is EXACT on the normalized host (lowercase, port stripped): a pattern selects
//! exactly the one host it names and can never match an unintended host. There is deliberately
//! no wildcard: a wildcard would be a footgun (a pattern that matches more hosts than intended
//! is a brand-confusion risk), and the per-scope partial unique index on `host_pattern` makes an
//! exact host the right granularity. This module is pure (no store, no IO), so the precedence is
//! unit-testable in isolation.

/// A candidate brand for selection (issue #86, PR 3): exactly the fields the precedence reads,
/// each a borrow of a stored brand row. The caller builds one per installed brand and passes the
/// slice to [`select_brand`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrandCandidate<'a> {
    /// The brand's per-environment natural key (the slug the render / serve path routes by).
    pub slug: &'a str,
    /// Whether this is the environment's DEFAULT brand (the tier-3 fallback).
    pub is_default: bool,
    /// The per-DOMAIN selection key, or [`None`]: the Host this brand is selected for.
    pub host_pattern: Option<&'a str>,
    /// The per-CLIENT selection key, or [`None`]: the `client_id` this brand is selected for.
    pub client_id: Option<&'a str>,
}

/// Normalize a Host header value for matching (issue #86, PR 3): trim, drop any `:port` suffix,
/// and lowercase. An IPv6 literal keeps its bracketed form (the port sits after the closing
/// bracket). An empty result yields [`None`] (there is no host to match on).
#[must_use]
pub fn normalize_host(raw: &str) -> Option<String> {
    let host = raw.trim();
    // For a bracketed IPv6 literal (`[::1]:443`) the port follows the closing bracket; for a
    // regular host the port follows the single colon. Split off the port accordingly.
    let without_port = if let Some(end) = host.strip_prefix('[').and_then(|_| host.find(']')) {
        // Keep through the closing bracket, dropping any `:port` after it.
        &host[..=end]
    } else {
        host.split(':').next().unwrap_or(host)
    };
    let normalized = without_port.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

/// Select the winning brand index by the precedence client > host > env-default > none (issue
/// #86, PR 3). `host` is the raw request Host (normalized here); `client_id` is the authorize
/// request's client id. Returns the index into `candidates` of the chosen brand, or [`None`]
/// when nothing matches and no default is installed (the caller then renders the neutral
/// default). The scan is deterministic (first match wins); the per-scope partial unique indexes
/// on `host_pattern` and `client_id` mean at most one candidate can match either selector, so
/// "first match" is also "the only match" in practice.
#[must_use]
pub fn select_brand(
    candidates: &[BrandCandidate<'_>],
    host: Option<&str>,
    client_id: Option<&str>,
) -> Option<usize> {
    // Tier 1: per-CLIENT. A brand whose client_id equals the request's client_id.
    if let Some(cid) = client_id {
        if let Some(index) = candidates.iter().position(|c| c.client_id == Some(cid)) {
            return Some(index);
        }
    }
    // Tier 2: per-DOMAIN. A brand whose normalized host_pattern equals the normalized request
    // Host. Both sides are normalized identically, so the match is exact and case-insensitive.
    if let Some(request_host) = host.and_then(normalize_host) {
        if let Some(index) = candidates.iter().position(|c| {
            c.host_pattern
                .and_then(normalize_host)
                .is_some_and(|pattern| pattern == request_host)
        }) {
            return Some(index);
        }
    }
    // Tier 3: the environment DEFAULT brand.
    if let Some(index) = candidates.iter().position(|c| c.is_default) {
        return Some(index);
    }
    // Tier 4: nothing installed / nothing matched -> the neutral default.
    None
}

#[cfg(test)]
mod tests {
    use super::{BrandCandidate, normalize_host, select_brand};

    fn candidate<'a>(
        slug: &'a str,
        is_default: bool,
        host_pattern: Option<&'a str>,
        client_id: Option<&'a str>,
    ) -> BrandCandidate<'a> {
        BrandCandidate {
            slug,
            is_default,
            host_pattern,
            client_id,
        }
    }

    #[test]
    fn normalize_host_lowercases_and_strips_port() {
        assert_eq!(
            normalize_host("Login.ACME.test"),
            Some("login.acme.test".into())
        );
        assert_eq!(
            normalize_host("login.acme.test:8443"),
            Some("login.acme.test".into())
        );
        assert_eq!(
            normalize_host("  Login.Acme.Test  "),
            Some("login.acme.test".into())
        );
        assert_eq!(normalize_host("[::1]:443"), Some("[::1]".into()));
        assert_eq!(normalize_host(""), None);
        assert_eq!(normalize_host("   "), None);
    }

    #[test]
    fn per_client_wins_over_per_domain_and_default() {
        // A client-selected brand, a domain-selected brand, and the env default all installed.
        let candidates = [
            candidate("default", true, None, None),
            candidate("acme_domain", false, Some("login.acme.test"), None),
            candidate("acme_client", false, None, Some("cli_acme")),
        ];
        // The request carries BOTH a matching host and a matching client: the client wins.
        let chosen = select_brand(&candidates, Some("login.acme.test"), Some("cli_acme"));
        assert_eq!(chosen.map(|i| candidates[i].slug), Some("acme_client"));
    }

    #[test]
    fn per_domain_wins_over_default_when_no_client_match() {
        let candidates = [
            candidate("default", true, None, None),
            candidate("acme_domain", false, Some("login.acme.test"), None),
        ];
        // A matching host, no client match: the domain brand wins over the default.
        let chosen = select_brand(
            &candidates,
            Some("login.acme.test:8443"),
            Some("cli_unknown"),
        );
        assert_eq!(chosen.map(|i| candidates[i].slug), Some("acme_domain"));
    }

    #[test]
    fn two_domains_on_one_env_select_distinct_brands() {
        // AC #2: two brands with distinct host_patterns render distinct per-domain brands.
        let candidates = [
            candidate("acme", false, Some("login.acme.test"), None),
            candidate("globex", false, Some("id.globex.test"), None),
        ];
        let acme = select_brand(&candidates, Some("login.acme.test"), None);
        let globex = select_brand(&candidates, Some("id.globex.test"), None);
        assert_eq!(acme.map(|i| candidates[i].slug), Some("acme"));
        assert_eq!(globex.map(|i| candidates[i].slug), Some("globex"));
    }

    #[test]
    fn falls_to_default_then_neutral() {
        let with_default = [
            candidate("default", true, None, None),
            candidate("acme", false, Some("login.acme.test"), None),
        ];
        // No host / client match: the env default is chosen.
        assert_eq!(
            select_brand(&with_default, Some("other.test"), Some("cli_none"))
                .map(|i| with_default[i].slug),
            Some("default")
        );
        // No default installed and no match: NONE (the neutral default).
        let no_default = [candidate("acme", false, Some("login.acme.test"), None)];
        assert_eq!(select_brand(&no_default, Some("other.test"), None), None);
        // An empty scope: NONE.
        assert_eq!(
            select_brand(&[], Some("login.acme.test"), Some("cli_x")),
            None
        );
    }

    #[test]
    fn a_non_matching_host_never_selects_an_unintended_brand() {
        // Exact match only: a superstring / substring host never matches a pattern.
        let candidates = [candidate("acme", false, Some("acme.test"), None)];
        assert_eq!(
            select_brand(&candidates, Some("evil-acme.test"), None),
            None
        );
        assert_eq!(
            select_brand(&candidates, Some("acme.test.evil.test"), None),
            None
        );
        // The exact host matches.
        assert_eq!(
            select_brand(&candidates, Some("ACME.test"), None).map(|i| candidates[i].slug),
            Some("acme")
        );
    }
}
