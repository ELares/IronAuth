// SPDX-License-Identifier: MIT OR Apache-2.0

//! Turning `[forward_auth]` configuration into a [`RuleSet`] (issue #154).
//!
//! `ironauth_config` owns the VOCABULARY and validates that a rule is internally coherent:
//! a capture name its pattern binds, an `acr` only where one means something, no rule that
//! can never fire. This module owns the other half, which config cannot know: whether this
//! BUILD can honour the rule it was handed.
//!
//! # Why a criterion can be valid and still be refused here
//!
//! `subject_in_group` and `subject_has_role` are in the vocabulary because the engine has
//! `SubjectCheck::InGroup` and `SubjectCheck::HasRole`. What decides whether they WORK is
//! the identity the forward-auth surface can build, and today that identity carries a
//! subject and nothing else: the role and group sources in the store are organization
//! scoped, and which organization's roles apply to a request that named no organization is
//! a question nobody has answered yet.
//!
//! So a rule using either is refused at conversion, loudly, rather than converted into a
//! check against an empty list. An empty `groups` makes `InGroup` always false, which turns
//! an `allow` rule into a rule that never fires and a `deny` rule into one that never bites.
//! The second is the dangerous direction: a deployment would read "deny anyone not in
//! `admins`" and get no denial at all.

use ironauth_config::{
    AccessActionConfig, AccessRuleConfig, ForwardAuthConfig, SubjectStateConfig,
};

use crate::rules::{Action, Criterion, Rule, RuleSet, SubjectCheck};

/// Why a validated rule could not be built into a [`RuleSet`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConversionError {
    /// The rule names a criterion this build cannot evaluate.
    Unsupported {
        /// The rule's operator-facing name.
        rule: String,
        /// The configuration field that cannot be honoured.
        field: &'static str,
        /// What the build cannot do, and what would happen if it pretended otherwise.
        why: &'static str,
    },
    /// The rule names an `acr` that is not a rung of this deployment's ladder.
    ///
    /// Refused rather than passed through, because an unranked `acr` is satisfied only by an
    /// exact string match against an ACHIEVED context, and no authentication achieves a value
    /// the registry does not issue. The two ways that lands are both silent:
    ///
    /// - on a `step-up` action the rule challenges a caller who then cannot ever satisfy it,
    ///   returns, and is challenged again -- the redirect loop [`crate::rules::Action::StepUp`]
    ///   documents, re-entered through a typo;
    /// - on `acr_at_least` the rule never fires, so an `allow` silently stops applying and a
    ///   `deny` silently stops biting.
    ///
    /// It also covers a rung that EXISTS but that this surface cannot observe. See
    /// [`unobservable_acr`]: a rule naming it enforces a different level from the one it
    /// reads as, which is the same defect wearing a valid value.
    UnknownAcr {
        /// The rule's operator-facing name.
        rule: String,
        /// The configuration field carrying it.
        field: &'static str,
        /// What the operator wrote.
        value: String,
        /// The rungs this deployment can actually reach.
        known: Vec<&'static str>,
    },
    /// A pattern that passed config validation failed to compile here.
    ///
    /// Config validates the same pattern with the same crate, so this should be
    /// unreachable. It is an error rather than an `expect` because a panic at boot in a
    /// path that parses operator input is a worse failure than a refusal.
    Pattern {
        /// The rule's operator-facing name.
        rule: String,
        /// The regex error.
        message: String,
    },
}

impl std::fmt::Display for ConversionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported { rule, field, why } => write!(
                f,
                "forward-auth rule `{rule}` uses `{field}`, which this build cannot \
                 evaluate: {why}"
            ),
            Self::UnknownAcr {
                rule,
                field,
                value,
                known,
            } => write!(
                f,
                "forward-auth rule `{rule}` sets `{field}` to `{value}`, which names no \
                 authentication level this deployment can reach: no session ever achieves \
                 it, so the rule would loop or would never fire. Known levels: {}",
                known.join(", ")
            ),
            Self::Pattern { rule, message } => write!(
                f,
                "forward-auth rule `{rule}` has a path_matches that failed to compile \
                 here despite passing configuration validation: {message}"
            ),
        }
    }
}

impl std::error::Error for ConversionError {}

/// Build the deployment's access rules, SHARED, from validated configuration.
///
/// Order is preserved exactly: the engine is first-match-wins, so the list IS the policy.
///
/// # Errors
///
/// [`ConversionError`] on the first rule this build cannot honour.
pub fn access_rules_from_config(
    cfg: &ForwardAuthConfig,
    acr_order: &[String],
) -> Result<std::sync::Arc<RuleSet>, ConversionError> {
    rule_set_from_config(cfg, acr_order).map(std::sync::Arc::new)
}

/// Build a [`RuleSet`] from validated configuration.
///
/// Prefer [`access_rules_from_config`] at a boot path: issue #154 criterion 4 asks that the
/// SAME rule set gate more than one consumer, and sharing one `Arc` is how that stops being a
/// claim about two objects that happen to agree.
///
/// Order is preserved exactly: the engine is first-match-wins, so the list IS the policy.
///
/// # Errors
///
/// [`ConversionError`] on the first rule this build cannot honour.
pub fn rule_set_from_config(
    cfg: &ForwardAuthConfig,
    acr_order: &[String],
) -> Result<RuleSet, ConversionError> {
    let mut rules = Vec::with_capacity(cfg.rules.len());
    for rule in &cfg.rules {
        rules.push(rule_from_config(rule)?);
    }
    let set = RuleSet::new(rules);
    // EMPTY MEANS "NOT CONFIGURED", which `oidc.acr_order` documents as falling back to the
    // canonical order at read time. `RuleSet::new` already carries that order, so passing the
    // empty list through would replace a real ladder with one that ranks nothing -- the
    // failure `RuleSet::default` exists to prevent, arriving by a different door.
    if acr_order.is_empty() {
        return Ok(set);
    }
    Ok(set.with_acr_order(acr_order.to_vec()))
}

/// Build one [`Rule`], refusing what this build cannot evaluate.
fn rule_from_config(cfg: &AccessRuleConfig) -> Result<Rule, ConversionError> {
    let unsupported = |field, why| ConversionError::Unsupported {
        rule: cfg.name.clone(),
        field,
        why,
    };

    // REFUSED BEFORE ANYTHING IS BUILT. Converting the rest first and failing at the end
    // would be the same answer, but it invites someone to "just skip" the unsupported
    // criterion later, which is the silent widening this exists to prevent.
    if cfg.subject_in_group.is_some() {
        return Err(unsupported(
            "subject_in_group",
            "the forward-auth identity carries a subject and no group memberships, so this \
             check would compare against an empty list: an `allow` rule would never fire \
             and a `deny` rule would never bite, which is the direction that leaves a \
             deployment believing it has a restriction it does not have",
        ));
    }
    if cfg.subject_has_role.is_some() {
        return Err(unsupported(
            "subject_has_role",
            "the forward-auth identity carries no roles, for the same reason: the role \
             sources in the store are organization scoped and a forward-auth request names \
             no organization",
        ));
    }

    let mut criteria = Vec::new();
    if !cfg.methods.is_empty() {
        criteria.push(Criterion::Method(cfg.methods.clone()));
    }
    if let Some(host) = &cfg.host {
        criteria.push(Criterion::Host(host.clone()));
    }
    if let Some(prefix) = &cfg.path_prefix {
        criteria.push(Criterion::PathPrefix(prefix.clone()));
    }
    // THE PATTERN GOES IN BEFORE ANY SUBJECT CHECK. `SubjectCheck::EqualsCapture` reads a
    // capture bound earlier in the SAME rule, and the engine evaluates criteria in order,
    // so a subject check placed ahead of the pattern would read an unbound name.
    if let Some(pattern) = &cfg.path_matches {
        let compiled = regex::Regex::new(pattern).map_err(|error| ConversionError::Pattern {
            rule: cfg.name.clone(),
            message: error.to_string(),
        })?;
        criteria.push(Criterion::PathMatches(compiled));
    }
    for header in &cfg.headers {
        criteria.push(Criterion::Header {
            name: header.name.clone(),
            value: header.value.clone(),
        });
    }
    if let Some(state) = cfg.subject_state {
        criteria.push(Criterion::Subject(match state {
            SubjectStateConfig::Authenticated => SubjectCheck::Authenticated,
            SubjectStateConfig::Anonymous => SubjectCheck::Anonymous,
        }));
    }
    if let Some(subject) = &cfg.subject_is {
        criteria.push(Criterion::Subject(SubjectCheck::Is(subject.clone())));
    }
    if let Some(capture) = &cfg.subject_equals_capture {
        criteria.push(Criterion::Subject(SubjectCheck::EqualsCapture(
            capture.clone(),
        )));
    }
    if let Some(floor) = &cfg.acr_at_least {
        criteria.push(Criterion::AcrAtLeast(canonical_acr(
            &cfg.name,
            "acr_at_least",
            floor,
        )?));
    }

    let action = match cfg.action {
        AccessActionConfig::Allow => Action::Allow,
        AccessActionConfig::Deny => Action::Deny,
        // Config validation guarantees `acr` is present and non-empty for step-up, so this
        // default is unreachable. It stays a default rather than an unwrap because a panic at
        // boot in a path that parses operator input is the worse failure -- and the empty
        // string is no longer a weak requirement that would quietly ship: `canonical_acr`
        // names no rung for it and refuses, so the unreachable arm now ends in an error
        // rather than in a step-up nobody can satisfy.
        AccessActionConfig::StepUp => Action::StepUp {
            acr: canonical_acr(&cfg.name, "acr", cfg.acr.as_deref().unwrap_or_default())?,
        },
    };

    Ok(Rule {
        name: cfg.name.clone(),
        criteria,
        action,
    })
}

/// The one ACR rung this surface can never observe, whatever an operator writes.
///
/// `mfa_remembered` is achieved by [`crate::AuthMethod::TrustedDevice`], and a trusted-device
/// contribution is frozen onto an AUTHORIZATION CODE for one request (`authorize.rs`) and is
/// never written back to the session. Every other rung reaches a session row, because every
/// other method establishes one: password, the OTP and magic-link paths, passkeys, federation,
/// SAML and recovery all mint a session through `interaction::establish_session` carrying what
/// they proved.
///
/// So a forward-auth request never presents this rung. A rule naming it does not fail loudly:
/// the value is RANKED, between `pwd` and `mfa`, so an `acr_at_least` floor naming it is an
/// exact synonym for `mfa` at this surface, and a `step-up` naming it terminates one rung above
/// what it says. Both read as enforcing the remembered-device level and enforce something else,
/// and a session whose TOKEN carries exactly this rung is refused by the rule that names it.
///
/// Read off the registry rather than written as a string, so renaming the rung moves this with
/// it.
fn unobservable_acr() -> &'static str {
    crate::AuthMethod::TrustedDevice.acr()
}

/// The `acr` an operator wrote, in the form the engine compares against, or a refusal.
///
/// # Canonicalising is not cosmetic
///
/// The achieved context a session carries is a canonical value (`urn:ironauth:acr:mfa`), and
/// an operator writing `mfa` means that rung. Comparing the two verbatim never matches, so a
/// `step-up` rule written the short way -- the way every operator-facing surface in this
/// project documents, and the way the CLI accepts -- would challenge a caller who has already
/// met it, forever. The alias is resolved here, once, against the same registry the achieved
/// value is derived from.
///
/// # Errors
///
/// [`ConversionError::UnknownAcr`] when the value names no rung, which is the other way the
/// same loop is reached.
fn canonical_acr(rule: &str, field: &'static str, value: &str) -> Result<String, ConversionError> {
    let trimmed = value.trim();
    let canonical = crate::step_up::canonical_step_up_acr(trimmed);
    if !crate::step_up::is_known_step_up_acr(trimmed) || canonical == unobservable_acr() {
        return Err(ConversionError::UnknownAcr {
            rule: rule.to_owned(),
            field,
            value: value.to_owned(),
            known: observable_step_up_acrs(),
        });
    }
    Ok(canonical)
}

/// The rungs a forward-auth request can actually present, for an operator-facing error.
///
/// `known_step_up_acrs` minus [`unobservable_acr`]. Listing a level the refusal itself would
/// reject would send an operator straight back into the same error.
fn observable_step_up_acrs() -> Vec<&'static str> {
    crate::step_up::known_step_up_acrs()
        .into_iter()
        .filter(|acr| *acr != unobservable_acr())
        .collect()
}

/// The forward-auth surface a boot path installs on the OIDC plane (issue #154).
///
/// Holds the compiled rules and the proxy dialect together, because reading a check request
/// requires both and separating them would let a deployment end up with rules from one
/// configuration and a dialect from another.
///
/// `Dialect::EnvoyExtAuthz` is deliberately unreachable from here: `ProxyDialectConfig` has
/// no value for it, because this build serves the check from a fixed route and `ext_authz`
/// carries the original PATH the way it carries the original method. See the note beside
/// `ProxyDialectConfig`.
pub struct ForwardAuthRuntime {
    forward_auth: crate::forward_auth::ForwardAuth,
    dialect: crate::forward_auth::Dialect,
    limiter: ironauth_quota::layered::LayeredLimiter,
    /// The seam clock, so `evaluate` can stamp the decision cache's TTL from the same time
    /// everything else in this process rides.
    clock: std::sync::Arc<dyn ironauth_env::Clock>,
}

impl ForwardAuthRuntime {
    /// Build the surface from validated configuration.
    ///
    /// Returns `Ok(None)` when the deployment did not enable forward-auth, which is not an
    /// error: an absent surface answers 404, and that is the shipped default.
    ///
    /// # Errors
    ///
    /// [`ConversionError`] when a rule is valid configuration this build cannot evaluate.
    /// Surfaced at boot rather than at request time, because a rule that cannot be built is
    /// a rule that does not apply, and a missing rule on an ordered access list hands the
    /// request to whatever follows it.
    ///
    /// `acr_order` is the deployment's `oidc.acr_order`, passed in rather than defaulted so
    /// that a forward-auth step-up and an OIDC step-up rank credential strength the same way.
    /// A deployment that reordered the ladder and had this surface keep the shipped one would
    /// have two policies, and the disagreement shows up as one plane admitting a session the
    /// other challenges.
    pub fn from_config(
        cfg: &ForwardAuthConfig,
        acr_order: &[String],
        clock: std::sync::Arc<dyn ironauth_env::Clock>,
    ) -> Result<Option<Self>, ConversionError> {
        Self::from_rules(cfg, access_rules_from_config(cfg, acr_order)?, clock)
    }

    /// The same, over rules a boot path already compiled.
    ///
    /// This is the constructor criterion 4 needs: the caller holds the `Arc` it passes here and
    /// installs the SAME one on the state the issuance gate reads, so the two consumers cannot
    /// drift onto different sets. `from_config` is the convenience for a caller with only one
    /// consumer.
    ///
    /// # Errors
    ///
    /// None today; the signature matches `from_config` so a caller can swap between them, and
    /// a future rule that only a configured surface can honour has somewhere to refuse.
    pub fn from_rules(
        cfg: &ForwardAuthConfig,
        rules: std::sync::Arc<RuleSet>,
        clock: std::sync::Arc<dyn ironauth_env::Clock>,
    ) -> Result<Option<Self>, ConversionError> {
        if !cfg.enabled {
            return Ok(None);
        }
        Ok(Some(Self {
            limiter: layered_limiter_from_config(&cfg.rate_limit, clock.clone()),
            forward_auth: match cfg.decision_cache_ttl_secs {
                // THE CACHE IS OFF BY DEFAULT (issue #154 criterion 6): a deployment that
                // has not asked for it gets the same evaluation it always had, and the
                // field documents what turning it on buys and what bounds it keeps.
                None => crate::forward_auth::ForwardAuth::new(rules),
                Some(seconds) => crate::forward_auth::ForwardAuth::with_decision_cache(
                    rules,
                    std::time::Duration::from_secs(seconds),
                ),
            },
            dialect: match cfg.dialect {
                ironauth_config::ProxyDialectConfig::ForwardAuth => {
                    crate::forward_auth::Dialect::ForwardAuth
                }
                ironauth_config::ProxyDialectConfig::NginxAuthRequest => {
                    crate::forward_auth::Dialect::NginxAuthRequest
                }
                ironauth_config::ProxyDialectConfig::Haproxy => {
                    crate::forward_auth::Dialect::Haproxy
                }
            },
            clock,
        }))
    }

    /// The compiled rules.
    #[must_use]
    pub fn forward_auth(&self) -> &crate::forward_auth::ForwardAuth {
        &self.forward_auth
    }

    /// Decide a check request, stamping the decision cache's TTL from this runtime's clock.
    #[must_use]
    pub fn evaluate(
        &self,
        facts: crate::rules::RequestFacts,
        identity: Option<&crate::forward_auth::Identity>,
    ) -> crate::forward_auth::ForwardAuthOutcome {
        self.forward_auth
            .evaluate(facts, identity, self.clock.monotonic())
    }

    /// The full trace for a hypothetical check request (issue #154 criterion 5), the
    /// dry-run half of "answer why was this denied".
    ///
    /// Decodes the request the way the check route does (the configured dialect reads the
    /// original request from its own headers), sanitises it the way the check route does,
    /// and returns every rule's answer WITHOUT deciding anything enforceable: the route
    /// that calls this is not the check route, and the dry-run types return no owned
    /// decision.
    #[must_use]
    pub fn explain(&self, facts: &crate::rules::RequestFacts) -> crate::rules::Explanation {
        self.forward_auth.explain(facts)
    }

    /// The dialect check requests arrive in.
    #[must_use]
    pub fn dialect(&self) -> crate::forward_auth::Dialect {
        self.dialect
    }

    /// The request-plane limiter this surface admits through.
    #[must_use]
    pub fn limiter(&self) -> &ironauth_quota::layered::LayeredLimiter {
        &self.limiter
    }
}

/// Build the five-layer limiter from configuration (issue #150 criterion 1).
///
/// A layer with no configured limit is left out, which the limiter treats as unlimited. All
/// five absent is the shipped default, so a deployment that has not asked to be rate limited
/// gets a limiter that admits everything rather than no limiter at all: one code path,
/// whether or not limits are configured, so the admit call site cannot drift into being
/// conditional and then being forgotten.
pub fn layered_limiter_from_config(
    cfg: &ironauth_config::RateLimitConfig,
    clock: std::sync::Arc<dyn ironauth_env::Clock>,
) -> ironauth_quota::layered::LayeredLimiter {
    use ironauth_quota::layered::{LayeredLimiter, LayeredLimits, RateLayer};

    let mut limits = LayeredLimits::unlimited();
    // PER-CLIENT IS MAPPED HERE because the SHARED builder serves surfaces that resolve a
    // client: the authorization path and the token endpoint key it on the verified client
    // identifier. A surface that names no client (the forward-auth check) still receives
    // the layer in its limits, and a request without a key for a CONFIGURED layer is
    // reported in the outcome's `unenforced` census rather than silently skipped.
    //
    // Per-USER is not mapped: no current surface resolves a subject before its limiter
    // runs, and an unenforceable layer would need a fifth census entry to stay honest.
    for (layer, configured) in [
        (RateLayer::PerIp, cfg.per_ip),
        (RateLayer::PerTenant, cfg.per_tenant),
        (RateLayer::PerEnvironment, cfg.per_environment),
        (RateLayer::PerClient, cfg.per_client),
    ] {
        if let Some(limit) = configured {
            limits = limits.with(
                layer,
                ironauth_quota::Limit::new(limit.per_second, limit.burst),
            );
        }
    }
    LayeredLimiter::new(limits, clock)
}

#[cfg(test)]
mod tests {
    /// Convert with no configured order, which reaches the SAME canonical ladder through the
    /// empty-list fallback, so a row that does not care about ranking is unaffected.
    ///
    /// This is NOT the shipped deployment, and an earlier version of this comment said it was
    /// ("`oidc.acr_order` defaults to empty"). It does not: `OidcConfig::default` fills it with
    /// the six-rung ladder and the section carries `#[serde(default)]`, so a file that never
    /// mentions the key still arrives here non-empty and `main.rs` passes it straight through.
    /// Believing otherwise is what left the pass-through untested --
    /// `the_from_config_seam_ranks_by_the_deployments_ladder` covers it.
    fn rule_set_from_config_test(cfg: &ForwardAuthConfig) -> Result<RuleSet, ConversionError> {
        rule_set_from_config(cfg, &[])
    }

    use ironauth_config::{HeaderMatchConfig, ProxyDialectConfig, SubjectStateConfig};

    use super::*;

    fn clock() -> std::sync::Arc<dyn ironauth_env::Clock> {
        std::sync::Arc::new(ironauth_env::ManualClock::new(
            std::time::SystemTime::UNIX_EPOCH,
        ))
    }

    fn rule(name: &str) -> AccessRuleConfig {
        AccessRuleConfig {
            name: name.to_owned(),
            action: AccessActionConfig::Deny,
            ..AccessRuleConfig::default()
        }
    }

    fn enabled(rules: Vec<AccessRuleConfig>) -> ForwardAuthConfig {
        ForwardAuthConfig {
            enabled: true,
            dialect: ProxyDialectConfig::default(),
            rules,
            ..ForwardAuthConfig::default()
        }
    }

    /// A criterion this build cannot evaluate is REFUSED, not skipped.
    ///
    /// The refusal matters most in the `deny` direction and the test says so: an empty
    /// `groups` makes `InGroup` always false, so a skipped criterion turns "deny anyone not
    /// in admins" into a rule that never bites, and the deployment reads its own config as
    /// a restriction it does not have.
    #[test]
    fn a_rule_reading_groups_or_roles_is_refused_with_the_field_named() {
        for (field, mutate) in [
            (
                "subject_in_group",
                (|r: &mut AccessRuleConfig| r.subject_in_group = Some("admins".to_owned()))
                    as fn(&mut AccessRuleConfig),
            ),
            ("subject_has_role", |r: &mut AccessRuleConfig| {
                r.subject_has_role = Some("editor".to_owned());
            }),
        ] {
            let mut cfg = rule("gate");
            mutate(&mut cfg);

            let error = rule_set_from_config_test(&enabled(vec![cfg]))
                .expect_err("a rule this build cannot evaluate is refused");

            match &error {
                ConversionError::Unsupported {
                    rule, field: named, ..
                } => {
                    assert_eq!(*named, field);
                    assert_eq!(rule, "gate", "the refusal names the rule an operator wrote");
                }
                other @ (ConversionError::Pattern { .. } | ConversionError::UnknownAcr { .. }) => {
                    panic!("expected an Unsupported refusal, got {other:?}")
                }
            }
            assert!(
                format!("{error}").contains(field),
                "the rendered error must name the field: {error}"
            );
        }
    }

    /// The contrast: everything else converts.
    ///
    /// Without this a conversion that refused EVERY rule would satisfy the test above.
    #[test]
    fn a_rule_using_only_supported_criteria_converts() {
        let cfg = AccessRuleConfig {
            name: "own resource".to_owned(),
            action: AccessActionConfig::Allow,
            methods: vec!["GET".to_owned()],
            host: Some("app.example".to_owned()),
            path_prefix: Some("/u".to_owned()),
            path_matches: Some("^/u/(?<user>[^/]+)/.*$".to_owned()),
            headers: vec![HeaderMatchConfig {
                name: "x-env".to_owned(),
                value: "prod".to_owned(),
            }],
            subject_state: Some(SubjectStateConfig::Authenticated),
            subject_equals_capture: Some("user".to_owned()),
            ..AccessRuleConfig::default()
        };

        let set =
            rule_set_from_config_test(&enabled(vec![cfg])).expect("supported criteria convert");
        let rules = set.rules();

        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "own resource");
        assert!(matches!(rules[0].action, Action::Allow));

        // BY CONTENT, NOT BY COUNT. This asserted `criteria.len() == 7`, which a review
        // pointed out cannot see a criterion dropped when another is duplicated, and cannot
        // see a criterion mapped to the WRONG variant at all.
        let kinds: Vec<String> = rules[0]
            .criteria
            .iter()
            .map(|criterion| match criterion {
                Criterion::Method(methods) => format!("method:{}", methods.join("|")),
                Criterion::Host(host) => format!("host:{host}"),
                Criterion::PathPrefix(prefix) => format!("prefix:{prefix}"),
                Criterion::PathMatches(pattern) => format!("pattern:{}", pattern.as_str()),
                Criterion::Header { name, value } => format!("header:{name}={value}"),
                Criterion::Subject(check) => format!("subject:{check:?}"),
                Criterion::AcrAtLeast(floor) => format!("acr_at_least:{floor}"),
            })
            .collect();

        assert_eq!(
            kinds,
            vec![
                "method:GET".to_owned(),
                "host:app.example".to_owned(),
                "prefix:/u".to_owned(),
                "pattern:^/u/(?<user>[^/]+)/.*$".to_owned(),
                "header:x-env=prod".to_owned(),
                "subject:Authenticated".to_owned(),
                "subject:EqualsCapture(\"user\")".to_owned(),
            ],
            "every configured criterion must reach the engine as the right variant, in the \
             order the engine walks them"
        );
    }

    /// Both `subject_state` values map to their own check.
    ///
    /// A review found the mapping untested: inverting `Authenticated` and `Anonymous` left
    /// every test green, and inverting THAT one turns "only signed-in callers" into "only
    /// anonymous callers", which on an allow rule admits exactly the people it excluded.
    #[test]
    fn each_subject_state_maps_to_its_own_check() {
        for (configured, expected) in [
            (SubjectStateConfig::Authenticated, "Authenticated"),
            (SubjectStateConfig::Anonymous, "Anonymous"),
        ] {
            let cfg = AccessRuleConfig {
                name: "state".to_owned(),
                action: AccessActionConfig::Deny,
                subject_state: Some(configured),
                ..AccessRuleConfig::default()
            };

            let set = rule_set_from_config_test(&enabled(vec![cfg])).expect("converts");
            let rendered = format!("{:?}", set.rules()[0].criteria);

            assert!(
                rendered.contains(expected),
                "{configured:?} must emit SubjectCheck::{expected}, got {rendered}"
            );
        }
    }

    /// THE PATTERN MUST PRECEDE THE SUBJECT CHECK THAT READS ITS CAPTURE.
    ///
    /// `SubjectCheck::EqualsCapture` reads a capture bound earlier in the SAME rule and the
    /// engine walks criteria in order, so a subject check emitted ahead of the pattern would
    /// read an unbound name and the rule would never match. Asserted as INDICES rather than
    /// by evaluating, because the bug is an ordering one and an evaluation test would pass
    /// on a rule that happened not to depend on the capture.
    #[test]
    fn the_path_pattern_is_emitted_before_the_capture_that_reads_it() {
        let cfg = AccessRuleConfig {
            name: "own resource".to_owned(),
            action: AccessActionConfig::Allow,
            path_matches: Some("^/u/(?<user>[^/]+)$".to_owned()),
            subject_equals_capture: Some("user".to_owned()),
            ..AccessRuleConfig::default()
        };

        let set = rule_set_from_config_test(&enabled(vec![cfg])).expect("converts");
        let criteria = &set.rules()[0].criteria;

        let pattern = criteria
            .iter()
            .position(|c| matches!(c, Criterion::PathMatches(_)))
            .expect("the pattern is emitted");
        let capture = criteria
            .iter()
            .position(|c| matches!(c, Criterion::Subject(SubjectCheck::EqualsCapture(_))))
            .expect("the capture check is emitted");

        assert!(
            pattern < capture,
            "the pattern binds the capture, so it must come first: pattern at {pattern}, \
             capture at {capture}"
        );
    }

    /// Order is the policy, so the conversion must not reorder rules.
    #[test]
    fn rule_order_is_preserved_exactly() {
        let names = ["first", "second", "third"];
        let set = rule_set_from_config_test(&enabled(names.iter().map(|n| rule(n)).collect()))
            .expect("converts");

        let got: Vec<&str> = set.rules().iter().map(|r| r.name.as_str()).collect();
        assert_eq!(got, names, "first-match-wins makes order the policy itself");
    }

    /// Disabled is not an error, and it builds nothing.
    #[test]
    fn a_disabled_section_builds_no_runtime() {
        let cfg = ForwardAuthConfig {
            enabled: false,
            // Rules present but the surface off: still nothing, and NOT a refusal.
            rules: vec![rule("unused")],
            ..ForwardAuthConfig::default()
        };

        assert!(
            ForwardAuthRuntime::from_config(&cfg, &[], clock())
                .expect("a disabled section is not an error")
                .is_none()
        );
    }

    /// Every dialect maps to its own engine variant.
    ///
    /// Driven off the list rather than one spot-check, because the failure this catches is
    /// two config variants mapping to one engine variant, which a single case cannot see.
    #[test]
    fn every_configured_dialect_maps_to_a_distinct_engine_dialect() {
        let pairs = [
            (
                ProxyDialectConfig::ForwardAuth,
                crate::forward_auth::Dialect::ForwardAuth,
            ),
            (
                ProxyDialectConfig::NginxAuthRequest,
                crate::forward_auth::Dialect::NginxAuthRequest,
            ),
            (
                ProxyDialectConfig::Haproxy,
                crate::forward_auth::Dialect::Haproxy,
            ),
        ];

        for (configured, expected) in pairs {
            let runtime = ForwardAuthRuntime::from_config(
                &ForwardAuthConfig {
                    enabled: true,
                    dialect: configured,
                    rules: vec![rule("any")],
                    ..ForwardAuthConfig::default()
                },
                &[],
                clock(),
            )
            .expect("converts")
            .expect("enabled builds a runtime");

            assert_eq!(
                runtime.dialect(),
                expected,
                "{configured:?} must map to its own dialect"
            );
        }
    }
    // ----------------------------------------------------------------------------------
    // The acr an operator writes, and the one the engine compares (issue #154 criterion 4).
    // ----------------------------------------------------------------------------------

    fn step_up_to(acr: &str) -> AccessRuleConfig {
        AccessRuleConfig {
            name: "gate".to_owned(),
            action: AccessActionConfig::StepUp,
            acr: Some(acr.to_owned()),
            path_prefix: Some("/payments".to_owned()),
            ..AccessRuleConfig::default()
        }
    }

    /// A SHORT ALIAS IS RESOLVED, and this is the difference between a working rule and a
    /// redirect loop.
    ///
    /// `mfa` is what the CLI accepts, what the configuration reference documents, and what an
    /// operator writes. The context a session ACHIEVES is the canonical `urn:` form. Comparing
    /// the two verbatim never matches, so the rule would challenge a caller who has already
    /// answered it, and keep challenging.
    ///
    /// Asserted by DECIDING, not by reading the built action: the built action agreeing with
    /// itself proves nothing about whether a real session satisfies it.
    #[test]
    fn a_short_alias_is_resolved_to_the_context_a_session_actually_achieves() {
        let set = rule_set_from_config_test(&enabled(vec![step_up_to("mfa")])).expect("converts");

        let achieved = crate::authn::achieved_acr(&crate::authn::parse_methods("pwd totp"));
        assert_ne!(
            achieved, "mfa",
            "the premise: what a session achieves is not spelled the way an operator writes it"
        );

        let decided = set.decide(&crate::rules::RequestFacts {
            method: "GET".to_owned(),
            host: "app.example".to_owned(),
            path: "/payments/transfer".to_owned(),
            subject: Some("alice".to_owned()),
            acr: Some(achieved.to_owned()),
            ..crate::rules::RequestFacts::default()
        });
        assert_eq!(
            decided.action,
            crate::rules::Action::Allow,
            "an operator writing `mfa` must be satisfied by a session that did MFA"
        );
    }

    /// AN ACR NAMING NO RUNG IS REFUSED AT BOOT, in both fields it can appear in.
    ///
    /// No session ever achieves a value the registry does not issue, so an unranked one is
    /// satisfied by nothing: on a `step-up` it loops, and on `acr_at_least` it silently turns
    /// an `allow` off and a `deny` into a restriction that never bites. Configuration
    /// validation cannot catch either, because the rungs come from the authentication
    /// registry and the config crate sits below it.
    #[test]
    fn an_acr_naming_no_rung_is_refused_with_the_field_and_the_known_levels() {
        let mut floor = rule("gate");
        floor.acr_at_least = Some("urn:example:acr:invented".to_owned());

        for (field, cfg) in [
            ("acr", step_up_to("urn:example:acr:invented")),
            ("acr_at_least", floor),
        ] {
            let error = rule_set_from_config_test(&enabled(vec![cfg]))
                .expect_err("an acr nothing achieves is refused");
            match &error {
                ConversionError::UnknownAcr {
                    rule,
                    field: named,
                    known,
                    ..
                } => {
                    assert_eq!(*named, field);
                    assert_eq!(rule, "gate");
                    assert!(
                        known.contains(&crate::step_up::canonical_step_up_acr("mfa").as_str()),
                        "the refusal lists the rungs an operator can pick from, so the \
                         message is actionable rather than only a rejection"
                    );
                }
                other => panic!("expected an UnknownAcr refusal for {field}, got {other:?}"),
            }
        }
    }

    /// `acr_at_least` BECOMES A CRITERION, so the vocabulary has a runtime behind it.
    ///
    /// A configuration field the conversion drops is worse than an absent one: the operator
    /// reads their own file as a restriction and the engine never applies it.
    #[test]
    fn acr_at_least_selects_rather_than_challenging() {
        let mut cfg = rule("strong-only");
        cfg.action = AccessActionConfig::Allow;
        cfg.acr_at_least = Some("mfa".to_owned());
        let set = rule_set_from_config_test(&enabled(vec![cfg])).expect("converts");

        let at = |methods: &str| crate::rules::RequestFacts {
            method: "GET".to_owned(),
            host: "app.example".to_owned(),
            path: "/x".to_owned(),
            subject: Some("alice".to_owned()),
            acr: Some(crate::authn::achieved_acr(&crate::authn::parse_methods(methods)).to_owned()),
            ..crate::rules::RequestFacts::default()
        };

        assert_eq!(
            set.decide(&at("pwd totp")).action,
            crate::rules::Action::Allow
        );
        let weak = set.decide(&at("pwd"));
        assert_eq!(
            weak.action,
            crate::rules::Action::Deny,
            "the rule does not apply to a weak session, and no rule below it admits"
        );
        assert_eq!(
            weak.matched, None,
            "a floor SELECTS: the rule did not match, rather than matching and challenging"
        );
    }

    /// THE LADDER SURVIVES `from_config`, which is the seam production actually takes.
    ///
    /// `rule_set_from_config` is covered with a reordered order below, but every other test
    /// reaches it directly. `ForwardAuthRuntime::from_config` is what `main.rs` calls, and
    /// replacing its `acr_order` argument with an empty slice left the whole suite green: the
    /// runtime would then rank by the shipped ladder while `OidcState::acr_order` ranks by the
    /// operator's, which is the two-policy failure the parameter exists to prevent.
    ///
    /// Asserted BEHAVIOURALLY, because `ForwardAuth` exposes no rule set: under an order that
    /// ranks `phr` BELOW `mfa` (the canonical ladder puts it above), a passkey session must be
    /// challenged by a rule demanding `mfa` rather than admitted.
    #[test]
    fn the_from_config_seam_ranks_by_the_deployments_ladder() {
        let phr_below_mfa: Vec<String> = [
            "urn:ironauth:acr:pwd",
            "urn:ironauth:acr:mfa_remembered",
            "phr",
            "phrh",
            "urn:ironauth:acr:mfa",
            "urn:ironauth:acr:attested_passkey",
        ]
        .iter()
        .map(|acr| (*acr).to_owned())
        .collect();

        let mut cfg = enabled(vec![step_up_to("mfa")]);
        cfg.rules[0].path_prefix = None;

        let passkey = crate::forward_auth::Identity {
            user: "alice".to_owned(),
            groups: Vec::new(),
            roles: Vec::new(),
            email: None,
            name: None,
            acr: Some(
                crate::authn::achieved_acr(&crate::authn::parse_methods("passkey")).to_owned(),
            ),
        };
        assert_eq!(
            passkey.acr.as_deref(),
            Some("phr"),
            "the premise: a passkey session reaches the rung this order demotes"
        );

        let facts = || crate::rules::RequestFacts {
            method: "GET".to_owned(),
            host: "app.example".to_owned(),
            path: "/anything".to_owned(),
            ..crate::rules::RequestFacts::default()
        };

        let under_default = ForwardAuthRuntime::from_config(&cfg, &[], clock())
            .expect("converts")
            .expect("enabled");
        assert_eq!(
            under_default
                .forward_auth()
                .evaluate(facts(), Some(&passkey), clock().monotonic())
                .decision
                .action,
            crate::rules::Action::Allow,
            "on the canonical ladder phr outranks mfa, so the step-up is already met"
        );

        let under_operator = ForwardAuthRuntime::from_config(&cfg, &phr_below_mfa, clock())
            .expect("converts")
            .expect("enabled");
        assert_eq!(
            under_operator
                .forward_auth()
                .evaluate(facts(), Some(&passkey), clock().monotonic())
                .decision
                .action,
            crate::rules::Action::StepUp {
                acr: crate::step_up::canonical_step_up_acr("mfa")
            },
            "the deployment ranked phr below mfa, so the same session must be challenged"
        );
    }

    /// A RUNG NO SESSION ROW RECORDS IS REFUSED, even though it is a real advertised level.
    ///
    /// `mfa_remembered` is achieved by a trusted device, and that contribution is frozen onto
    /// an authorization code rather than written back to the session. A forward-auth check
    /// reads the session, so it never presents this rung: a floor naming it is an exact synonym
    /// for `mfa` here, and a step-up naming it terminates one rung above what it says.
    ///
    /// Derived from the registry on both sides, so renaming the rung moves the test with it.
    #[test]
    fn the_rung_this_surface_cannot_observe_is_refused_and_left_out_of_the_advice() {
        let unobservable = unobservable_acr();
        assert!(
            crate::step_up::known_step_up_acrs().contains(&unobservable),
            "the premise: this is an advertised level, so nothing else would refuse it"
        );

        let mut floor = rule("gate");
        floor.acr_at_least = Some(unobservable.to_owned());
        for cfg in [step_up_to(unobservable), floor] {
            match rule_set_from_config_test(&enabled(vec![cfg]))
                .expect_err("a rung this surface never sees is refused")
            {
                ConversionError::UnknownAcr { known, .. } => assert!(
                    !known.contains(&unobservable),
                    "the advice must not offer the level it just refused"
                ),
                other => panic!("expected UnknownAcr, got {other:?}"),
            }
        }

        // ...and every OTHER advertised rung still converts, so this is one exclusion rather
        // than a narrowing of the vocabulary.
        for acr in observable_step_up_acrs() {
            rule_set_from_config_test(&enabled(vec![step_up_to(acr)]))
                .unwrap_or_else(|error| panic!("{acr} must still convert: {error}"));
        }
    }

    /// THE REFUSAL TELLS AN OPERATOR WHAT TO WRITE INSTEAD.
    ///
    /// The `Display` arm is the only thing that reaches an operator when boot fails, and it was
    /// the one refusal in this file with no assertion on its rendering.
    #[test]
    fn the_unknown_acr_refusal_names_the_rule_the_field_and_the_levels() {
        let rendered = rule_set_from_config_test(&enabled(vec![step_up_to("strong")]))
            .expect_err("no rung is named `strong`")
            .to_string();
        for expected in ["gate", "`acr`", "strong", "no authentication level"] {
            assert!(
                rendered.contains(expected),
                "the refusal must contain {expected}; got {rendered}"
            );
        }
        assert!(
            rendered.contains(&crate::step_up::canonical_step_up_acr("mfa")),
            "and must list a level that does convert; got {rendered}"
        );
    }

    /// THE DEPLOYMENT'S LADDER REACHES THIS SURFACE, and an unset one does not blank it.
    ///
    /// Two failures in one test because they are the same field read two ways. A configured
    /// `oidc.acr_order` that stopped here would leave forward-auth ranking by the shipped
    /// ladder while the OIDC plane ranks by the operator's, so one plane admits a session the
    /// other challenges. An EMPTY list means "not configured" and must fall back to the
    /// canonical order, not install an order that ranks nothing.
    #[test]
    fn the_configured_acr_order_reaches_the_rules_and_an_empty_one_falls_back() {
        let cfg = enabled(vec![step_up_to("mfa")]);

        assert_eq!(
            rule_set_from_config(&cfg, &[])
                .expect("converts")
                .acr_order(),
            crate::step_up::default_acr_order(),
            "unset is the shipped ladder, not an empty one"
        );

        let mut inverted = crate::step_up::default_acr_order();
        inverted.reverse();
        assert_eq!(
            rule_set_from_config(&cfg, &inverted)
                .expect("converts")
                .acr_order(),
            inverted
        );
    }
}

#[cfg(test)]
mod limiter_tests {
    use ironauth_config::{ForwardAuthConfig, LimitConfig, RateLimitConfig};
    use ironauth_quota::Decision;
    use ironauth_quota::layered::{RateLayer, RequestIdentity};

    use super::*;

    fn clock() -> std::sync::Arc<dyn ironauth_env::Clock> {
        std::sync::Arc::new(ironauth_env::ManualClock::new(
            std::time::SystemTime::UNIX_EPOCH,
        ))
    }

    /// EVERY CONFIGURED LAYER REACHES THE LIMITER, driven off the list rather than one case.
    ///
    /// The failure a single spot-check cannot see is two config fields mapping to one layer:
    /// the build would still produce a limiter, the test would still pass, and one of the two
    /// budgets would silently not exist.
    ///
    /// Three layers, not five. Per-user and per-client are deliberately absent from the
    /// config because this surface cannot key them, and the assertion below pins that: if
    /// someone adds either field back without also resolving a subject before the limiter,
    /// the count stops matching and they have to confront the question rather than ship a
    /// budget that never binds.
    #[test]
    fn each_configured_layer_becomes_its_own_budget() {
        let one = Some(LimitConfig {
            per_second: 0.0,
            burst: 1.0,
        });
        let cases = [
            (
                RateLayer::PerIp,
                RateLimitConfig {
                    per_ip: one,
                    ..RateLimitConfig::default()
                },
            ),
            (
                RateLayer::PerTenant,
                RateLimitConfig {
                    per_tenant: one,
                    ..RateLimitConfig::default()
                },
            ),
            (
                RateLayer::PerEnvironment,
                RateLimitConfig {
                    per_environment: one,
                    ..RateLimitConfig::default()
                },
            ),
        ];

        // The identity the HANDLER builds, which is the point: it presents an address and a
        // scope and nothing else. Using an identity that presented a user would have let a
        // per-user budget appear to work here while never binding in production.
        let as_the_handler_builds_it = || RequestIdentity {
            ip: Some("198.51.100.7".to_owned()),
            user: None,
            client: None,
            tenant: Some("tnt_1".to_owned()),
            environment: Some("env_1".to_owned()),
        };
        assert_eq!(
            cases.len(),
            3,
            "three layers are keyable from this identity; a fourth case means the identity \
             grew and the config should say so"
        );

        for (expected, cfg) in cases {
            let limiter = layered_limiter_from_config(&cfg, clock());
            assert_eq!(
                limiter.admit(&as_the_handler_builds_it(), 1.0).decision,
                Decision::Admitted
            );
            let refused = limiter.admit(&as_the_handler_builds_it(), 1.0);

            assert!(refused.is_throttled(), "{expected:?} must bind");
            assert_eq!(
                refused.limiting_layer,
                Some(expected),
                "{expected:?} was configured, so it must be the layer that refuses"
            );
        }
    }

    /// CRITERION 1's ACTUAL CLAIM: the limiting layer is identified in headers AND metrics,
    /// and those two must be the SAME string.
    ///
    /// Asserted as an equality between the header value and the metric label rather than
    /// against a literal, because the harm is not either being wrong on its own: it is a
    /// dashboard and a response disagreeing about what a layer is called, which sends whoever
    /// is holding the 429 and whoever is reading the graph to different answers.
    #[test]
    fn the_refusing_layer_is_the_same_string_in_the_header_and_the_metric() {
        let limiter = layered_limiter_from_config(
            &RateLimitConfig {
                per_tenant: Some(LimitConfig {
                    per_second: 0.0,
                    burst: 1.0,
                }),
                ..RateLimitConfig::default()
            },
            clock(),
        );
        let identity = RequestIdentity {
            tenant: Some("tnt_1".to_owned()),
            ..RequestIdentity::default()
        };

        assert_eq!(limiter.admit(&identity, 1.0).decision, Decision::Admitted);
        let refused = limiter.admit(&identity, 1.0);

        let label = refused.metric_label().expect("a refusal names its layer");
        let headers = refused.headers();
        let header = headers
            .iter()
            .find(|(name, _)| *name == ironauth_quota::layered::LIMITING_LAYER_HEADER)
            .map(|(_, value)| value.as_str())
            .expect("a refusal carries the layer header");

        assert_eq!(
            label, header,
            "the metric label and the response header must be one string"
        );
        assert_eq!(label, "per_tenant");
    }

    /// The shipped default limits nothing, so a deployment that did not ask to be rate
    /// limited is not.
    ///
    /// This is the contrast the table above needs: without it, a `limiter_from_config` that
    /// returned a limiter refusing everything would satisfy every row.
    #[test]
    fn the_default_configuration_admits_everything() {
        let limiter =
            layered_limiter_from_config(&ForwardAuthConfig::default().rate_limit, clock());
        let identity = RequestIdentity {
            ip: Some("198.51.100.7".to_owned()),
            tenant: Some("tnt_1".to_owned()),
            ..RequestIdentity::default()
        };

        for spend in 0..50 {
            assert_eq!(
                limiter.admit(&identity, 1.0).decision,
                Decision::Admitted,
                "spend {spend}: an unconfigured limiter must not limit"
            );
        }
    }
}
