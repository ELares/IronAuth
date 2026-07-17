// SPDX-License-Identifier: MIT OR Apache-2.0

//! Enterprise inbound routing: the PURE routing decision (issue #77).
//!
//! An inbound login is routed to an organization's upstream identity provider by one
//! of three selectors, evaluated in a documented precedence. This module owns exactly
//! the decision logic and the email-domain normalization, with NO I/O: the caller (the
//! login surface) performs the scoped, row-level-security-forced store lookups and
//! hands the matched rules here, so the routing algorithm is small and unit-testable.
//!
//! # Precedence
//!
//! **per-user > per-app > per-domain** (most-specific-wins). A rule that names a single
//! user is the most specific and wins over a rule that names the app the login came
//! from, which in turn wins over a rule that names only the user's email domain. The
//! first hit in that order is the route; no hit falls through to the ordinary local
//! login prompt (fail-safe to local).
//!
//! # Collision-safety
//!
//! Within a scope, at most ONE enabled rule can match a given selector (a domain, an
//! app, or a user): the routing-rule table enforces that with three per-scope partial
//! unique indexes, so two organizations can never both claim one domain (the
//! org-A-cannot-reach-org-B property). This module therefore never has to disambiguate
//! two rules of the same kind; each candidate is at most one rule.

use ironauth_store::RoutingRuleRecord;

/// The candidate routing rules the caller resolved for one login, at most one per
/// selector kind (each selector resolves at most one enabled rule through its per-scope
/// unique index). The pure [`resolve_route`] decision reads these in precedence order.
#[derive(Debug, Default)]
pub struct RouteCandidates {
    /// The rule matching this exact user, if any (the most specific selector).
    pub user: Option<RoutingRuleRecord>,
    /// The rule matching the app the login came from, if any.
    pub app: Option<RoutingRuleRecord>,
    /// The rule matching the user's email domain, if any (the least specific selector).
    pub domain: Option<RoutingRuleRecord>,
}

/// Resolve the routing decision for one login from its candidate rules (issue #77).
///
/// The precedence is per-user > per-app > per-domain (most-specific-wins, documented on
/// this module): the user rule wins over the app rule, which wins over the domain rule.
/// Returns the winning rule, or [`None`] when no selector matched (the login then falls
/// through to the ordinary local prompt). Pure: no I/O, so the precedence is directly
/// unit-testable.
#[must_use]
pub fn resolve_route(candidates: &RouteCandidates) -> Option<&RoutingRuleRecord> {
    candidates
        .user
        .as_ref()
        .or(candidates.app.as_ref())
        .or(candidates.domain.as_ref())
}

/// The normalized email DOMAIN of a submitted login `identifier`, or [`None`] when the
/// identifier is not an email or its domain normalizes to empty (issue #77).
///
/// The domain is split on the LAST `@` and normalized through the ONE routing-domain
/// normalization (NFKC plus case-fold, `ironauth_store::normalize_routing_domain`), the
/// SAME normalization a routing rule's domain selector is stored under, so a rule stored
/// for `Example.COM` matches a login submitted as `alice@example.com`. Pure.
///
/// The split is on the ASCII `@` AND the compatibility at-signs that NFKC folds onto it
/// (the fullwidth commercial at U+FF20 and the small commercial at U+FE6B), so an
/// identifier written with a fullwidth at-sign routes by domain identically to its ASCII
/// form. Folding these BEFORE the split keeps the split consistent with the rest of the
/// identifier seam, which NFKC-folds them (issue #77, L2): otherwise `alice＠acme.example`
/// would find no domain while the store canonicalized it to `alice@acme.example`.
#[must_use]
pub fn normalize_email_domain(identifier: &str) -> Option<String> {
    let folded = identifier.replace(['\u{FF20}', '\u{FE6B}'], "@");
    let (_local, domain) = folded.rsplit_once('@')?;
    ironauth_store::normalize_routing_domain(domain)
}

#[cfg(test)]
mod tests {
    use super::{RouteCandidates, normalize_email_domain, resolve_route};
    use ironauth_store::{RoutingRuleId, RoutingRuleRecord, Scope};

    fn rule(org_connection_id: &str) -> RoutingRuleRecord {
        // A scope only to mint a well-formed rrl_ id for the record; the routing
        // decision reads only org_connection_id, so the other fields are placeholders.
        let (env, _clock) = ironauth_env::Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 1);
        let tenant = ironauth_store::TenantId::generate(&env);
        let environment = ironauth_store::EnvironmentId::generate(&env);
        let scope = Scope::new(tenant, environment);
        RoutingRuleRecord {
            id: RoutingRuleId::generate(&env, &scope),
            rule_kind: "domain".to_owned(),
            domain_norm: None,
            client_id: None,
            user_bidx: None,
            org_connection_id: org_connection_id.to_owned(),
            priority: 0,
            enabled: true,
            created_at_unix_micros: 0,
            updated_at_unix_micros: 0,
        }
    }

    #[test]
    fn no_candidate_resolves_to_no_route() {
        let candidates = RouteCandidates::default();
        assert!(
            resolve_route(&candidates).is_none(),
            "no selector matched, so the login falls through to local"
        );
    }

    #[test]
    fn a_domain_only_match_routes_to_the_domain_rule() {
        let candidates = RouteCandidates {
            user: None,
            app: None,
            domain: Some(rule("ocn_domain")),
        };
        assert_eq!(
            resolve_route(&candidates).unwrap().org_connection_id,
            "ocn_domain"
        );
    }

    #[test]
    fn per_app_overrides_per_domain() {
        let candidates = RouteCandidates {
            user: None,
            app: Some(rule("ocn_app")),
            domain: Some(rule("ocn_domain")),
        };
        assert_eq!(
            resolve_route(&candidates).unwrap().org_connection_id,
            "ocn_app",
            "an app rule is more specific than a domain rule"
        );
    }

    #[test]
    fn per_user_overrides_per_app_and_per_domain() {
        let candidates = RouteCandidates {
            user: Some(rule("ocn_user")),
            app: Some(rule("ocn_app")),
            domain: Some(rule("ocn_domain")),
        };
        assert_eq!(
            resolve_route(&candidates).unwrap().org_connection_id,
            "ocn_user",
            "a user rule is the most specific and wins over app and domain"
        );
    }

    #[test]
    fn email_domain_is_extracted_and_normalized() {
        assert_eq!(
            normalize_email_domain("alice@Example.COM").as_deref(),
            Some("example.com"),
            "the domain is case-folded"
        );
        // A fullwidth commercial-at plus a fullwidth domain still normalizes (NFKC).
        assert_eq!(
            normalize_email_domain("bob@EXAMPLE.ORG").as_deref(),
            Some("example.org")
        );
        // The LAST @ splits, so a quoted local part keeps its own @ out of the domain.
        assert_eq!(
            normalize_email_domain("weird@name@acme.example").as_deref(),
            Some("acme.example")
        );
        // A FULLWIDTH commercial at (U+FF20) routes by domain identically to the ASCII
        // form: the identifier seam NFKC-folds it, so the split must agree (issue #77, L2).
        assert_eq!(
            normalize_email_domain("alice\u{FF20}acme.example").as_deref(),
            normalize_email_domain("alice@acme.example").as_deref(),
            "a fullwidth at-sign routes like an ASCII at-sign"
        );
        assert_eq!(
            normalize_email_domain("alice\u{FF20}acme.example").as_deref(),
            Some("acme.example")
        );
    }

    #[test]
    fn a_non_email_identifier_has_no_routable_domain() {
        assert!(normalize_email_domain("just-a-username").is_none());
        assert!(
            normalize_email_domain("trailing@").is_none(),
            "an empty domain is not routable"
        );
    }
}
