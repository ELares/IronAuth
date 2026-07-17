// SPDX-License-Identifier: MIT OR Apache-2.0

//! Disposable / low-reputation email domain evaluation at signup (issue #80).
//!
//! Evaluated on the NFKC-normalized email domain, per-environment configurable: `off` (no
//! check), `flag` (admit but feed the #79 risk engine a signal, so a proof-of-work
//! challenge may be required), or `block` (refuse with an ANTI-ENUMERATION uniform failure
//! indistinguishable from an ordinary validation error). The domain list is updateable
//! per-environment DATA (the config `denylist`/`allowlist`, like the #79 IP allow/deny
//! lists), not compiled in; an ALLOW override always admits a domain even if it matches the
//! deny list. The block response reuses the #64/#68 uniform-failure discipline, so a
//! disposable-domain block does not leak whether the identifier already exists.

use ironauth_config::DisposableEmailConfig;

/// The evaluated disposable-email decision (issue #80).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisposableDecision {
    /// The defense is off, the identifier is not an email, or the domain is allow-listed:
    /// admit with no risk signal.
    Allow,
    /// The domain is disposable and the mode is `flag`: ADMIT but contribute a risk
    /// signal (so a challenge may be required). Never leaks to the user.
    Flag,
    /// The domain is disposable and the mode is `block`: REFUSE with an anti-enumeration
    /// uniform failure.
    Block,
}

impl DisposableDecision {
    /// Whether this decision REFUSES the signup.
    #[must_use]
    pub fn is_block(self) -> bool {
        matches!(self, DisposableDecision::Block)
    }

    /// Whether this decision contributes a risk SIGNAL (a flagged disposable domain).
    #[must_use]
    pub fn is_flagged(self) -> bool {
        matches!(self, DisposableDecision::Flag)
    }
}

/// Extract the lower-cased domain of `email` (issue #80): the substring after the LAST `@`,
/// lower-cased, with a single trailing root dot stripped. Returns `None` when `email` has no
/// `@` or an empty domain (not an email identifier, so the disposable check does not apply).
/// The caller passes the NFKC-normalized identifier, so a Unicode homograph folds to one
/// form before the comparison.
#[must_use]
pub fn email_domain(email: &str) -> Option<String> {
    let (_local, domain) = email.rsplit_once('@')?;
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() {
        None
    } else {
        Some(domain)
    }
}

/// Whether `domain` matches any entry of `list` (issue #80): a case-insensitive exact match
/// on the domain, or a match on a parent domain (an entry `mailinator.com` also matches
/// `sub.mailinator.com`), so a deny-list entry covers a provider's subdomains.
fn domain_matches(domain: &str, list: &[String]) -> bool {
    list.iter().any(|entry| {
        let entry = entry.trim().trim_end_matches('.').to_ascii_lowercase();
        if entry.is_empty() {
            return false;
        }
        domain == entry || domain.ends_with(&format!(".{entry}"))
    })
}

/// Evaluate the disposable-email defense for a signup `identifier` (issue #80), already
/// NFKC-normalized by the caller. Returns [`DisposableDecision::Allow`] when the defense is
/// off, the identifier is not an email, or the domain is allow-listed (the override wins);
/// otherwise the domain is compared against the deny list and the configured mode selects
/// `Flag` or `Block`.
#[must_use]
pub fn evaluate(config: &DisposableEmailConfig, identifier: &str) -> DisposableDecision {
    // Off (the default) is fully inert.
    if config.mode == "off" {
        return DisposableDecision::Allow;
    }
    let Some(domain) = email_domain(identifier) else {
        return DisposableDecision::Allow;
    };
    // The ALLOW override wins over the deny list: an explicitly allow-listed domain is
    // always admitted, even if it also matches a deny entry or a heuristic.
    if domain_matches(&domain, &config.allowlist) {
        return DisposableDecision::Allow;
    }
    if !domain_matches(&domain, &config.denylist) {
        return DisposableDecision::Allow;
    }
    match config.mode.as_str() {
        "block" => DisposableDecision::Block,
        // Any non-off, non-block mode that reached here is `flag` (the config validator
        // pins the closed set, so this is only ever `flag`).
        _ => DisposableDecision::Flag,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(mode: &str, deny: &[&str], allow: &[&str]) -> DisposableEmailConfig {
        DisposableEmailConfig {
            mode: mode.to_owned(),
            denylist: deny.iter().map(|s| (*s).to_owned()).collect(),
            allowlist: allow.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    #[test]
    fn extracts_the_lowercased_domain() {
        assert_eq!(
            email_domain("Alice@Example.COM").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            email_domain("a@b@mailinator.com").as_deref(),
            Some("mailinator.com")
        );
        assert_eq!(email_domain("no-at-sign"), None);
        assert_eq!(
            email_domain("trailing@dot.com."),
            Some("dot.com".to_owned())
        );
        assert_eq!(email_domain("empty@"), None);
    }

    #[test]
    fn off_mode_admits_everything() {
        let cfg = config("off", &["mailinator.com"], &[]);
        assert_eq!(
            evaluate(&cfg, "bot@mailinator.com"),
            DisposableDecision::Allow
        );
    }

    #[test]
    fn block_mode_blocks_a_denied_domain_and_its_subdomains() {
        let cfg = config("block", &["mailinator.com"], &[]);
        assert_eq!(
            evaluate(&cfg, "bot@mailinator.com"),
            DisposableDecision::Block
        );
        assert_eq!(
            evaluate(&cfg, "bot@x.mailinator.com"),
            DisposableDecision::Block
        );
        assert_eq!(
            evaluate(&cfg, "real@example.com"),
            DisposableDecision::Allow
        );
    }

    #[test]
    fn flag_mode_flags_but_admits() {
        let cfg = config("flag", &["mailinator.com"], &[]);
        assert_eq!(
            evaluate(&cfg, "bot@mailinator.com"),
            DisposableDecision::Flag
        );
        assert!(evaluate(&cfg, "bot@mailinator.com").is_flagged());
    }

    #[test]
    fn allow_override_wins_over_deny() {
        let cfg = config("block", &["mailinator.com"], &["good.mailinator.com"]);
        assert_eq!(
            evaluate(&cfg, "vip@good.mailinator.com"),
            DisposableDecision::Allow
        );
        // A sibling subdomain is still blocked.
        assert_eq!(
            evaluate(&cfg, "bot@bad.mailinator.com"),
            DisposableDecision::Block
        );
    }

    #[test]
    fn a_non_email_identifier_is_never_disposable() {
        let cfg = config("block", &["mailinator.com"], &[]);
        assert_eq!(evaluate(&cfg, "just-a-username"), DisposableDecision::Allow);
    }
}
