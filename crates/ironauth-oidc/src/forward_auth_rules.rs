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
            Self::Pattern { rule, message } => write!(
                f,
                "forward-auth rule `{rule}` has a path_matches that failed to compile \
                 here despite passing configuration validation: {message}"
            ),
        }
    }
}

impl std::error::Error for ConversionError {}

/// Build a [`RuleSet`] from validated configuration.
///
/// Order is preserved exactly: the engine is first-match-wins, so the list IS the policy.
///
/// # Errors
///
/// [`ConversionError`] on the first rule this build cannot honour.
pub fn rule_set_from_config(cfg: &ForwardAuthConfig) -> Result<RuleSet, ConversionError> {
    let mut rules = Vec::with_capacity(cfg.rules.len());
    for rule in &cfg.rules {
        rules.push(rule_from_config(rule)?);
    }
    Ok(RuleSet::new(rules))
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

    let action = match cfg.action {
        AccessActionConfig::Allow => Action::Allow,
        AccessActionConfig::Deny => Action::Deny,
        // Config validation guarantees `acr` is present and non-empty for step-up, so this
        // default is unreachable. It is a default rather than an unwrap because an empty
        // acr is a weaker requirement than a panic is a failure.
        AccessActionConfig::StepUp => Action::StepUp {
            acr: cfg.acr.clone().unwrap_or_default(),
        },
    };

    Ok(Rule {
        name: cfg.name.clone(),
        criteria,
        action,
    })
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
    pub fn from_config(cfg: &ForwardAuthConfig) -> Result<Option<Self>, ConversionError> {
        if !cfg.enabled {
            return Ok(None);
        }
        Ok(Some(Self {
            forward_auth: crate::forward_auth::ForwardAuth::new(rule_set_from_config(cfg)?),
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
        }))
    }

    /// The compiled rules.
    #[must_use]
    pub fn forward_auth(&self) -> &crate::forward_auth::ForwardAuth {
        &self.forward_auth
    }

    /// The dialect check requests arrive in.
    #[must_use]
    pub fn dialect(&self) -> crate::forward_auth::Dialect {
        self.dialect
    }
}

#[cfg(test)]
mod tests {
    use ironauth_config::{HeaderMatchConfig, ProxyDialectConfig, SubjectStateConfig};

    use super::*;

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

            let error = rule_set_from_config(&enabled(vec![cfg]))
                .expect_err("a rule this build cannot evaluate is refused");

            match &error {
                ConversionError::Unsupported {
                    rule, field: named, ..
                } => {
                    assert_eq!(*named, field);
                    assert_eq!(rule, "gate", "the refusal names the rule an operator wrote");
                }
                other @ ConversionError::Pattern { .. } => {
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

        let set = rule_set_from_config(&enabled(vec![cfg])).expect("supported criteria convert");
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

            let set = rule_set_from_config(&enabled(vec![cfg])).expect("converts");
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

        let set = rule_set_from_config(&enabled(vec![cfg])).expect("converts");
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
        let set = rule_set_from_config(&enabled(names.iter().map(|n| rule(n)).collect()))
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
            ForwardAuthRuntime::from_config(&cfg)
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
            let runtime = ForwardAuthRuntime::from_config(&ForwardAuthConfig {
                enabled: true,
                dialect: configured,
                rules: vec![rule("any")],
            })
            .expect("converts")
            .expect("enabled builds a runtime");

            assert_eq!(
                runtime.dialect(),
                expected,
                "{configured:?} must map to its own dialect"
            );
        }
    }
}
