// SPDX-License-Identifier: MIT OR Apache-2.0

//! The ordered access-rule engine (issue #154, criterion 3).
//!
//! > The rules engine resolves ordered first-match correctly across all criteria types,
//! > including regex capture into subject checks, covered by a table-driven test corpus.
//!
//! One rule set, evaluated the same way wherever it is consulted. Criterion 4 asks that the
//! SAME rules gate a forward-auth resource, an OIDC token issuance and a step-up
//! requirement, so the engine takes a [`RequestFacts`] that none of those three surfaces
//! owns, and returns an [`Action`] that each interprets in its own terms.
//!
//! # First match wins, and order is the operator's tool
//!
//! Rules are evaluated in the order written and the first whose criteria ALL hold decides.
//! That is the shape operators already know from firewall and proxy rule lists, and it is
//! what makes a narrow exception above a broad deny work.
//!
//! The alternative -- most-specific-wins -- reads as friendlier and is worse here, because
//! "specific" has no order anyone can see: two rules matching different criteria types have
//! no natural ranking, and an operator debugging a denial cannot tell by reading which one
//! fired. With first match they can point at a line.
//!
//! # No implicit allow
//!
//! A request matching no rule is DENIED ([`Decision::no_match`]). A rule engine whose
//! fall-through admits is one forgotten rule away from an open door, and the failure is
//! silent: everything works, which is exactly what it looks like when nothing is enforced.
//!
//! # Captures feed subject checks, which is the point of having them
//!
//! `/users/(?P<uid>[^/]+)` matched against `/users/alice` binds `uid = alice`. A later
//! criterion in the SAME rule can require the authenticated subject to equal that capture,
//! which expresses "a person may read their own record" as one rule instead of one per
//! person.
//!
//! Captures are scoped to the rule that produced them. Leaking them across rules would let a
//! later rule silently depend on an earlier rule's pattern, so moving a rule -- the one
//! operation this engine's ordering invites -- would change the meaning of a rule that was
//! not touched.

use std::collections::HashMap;

use regex::Regex;

/// What a matching rule decides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Admit the request.
    Allow,
    /// Refuse it.
    Deny,
    /// Admit only with a stronger authentication, naming the required ACR.
    ///
    /// Distinct from `Deny` because the caller can DO something about it: a forward-auth
    /// surface redirects to re-authenticate, and a token endpoint answers the RFC 9470
    /// `insufficient_user_authentication` challenge.
    StepUp {
        /// The authentication context class the request must reach.
        acr: String,
    },
}

/// One thing that must hold for a rule to match.
#[derive(Debug, Clone)]
pub enum Criterion {
    /// The request method is one of these (compared case-insensitively).
    Method(Vec<String>),
    /// The request host equals this, case-insensitively.
    Host(String),
    /// The path starts with this literal prefix.
    PathPrefix(String),
    /// The path matches this pattern; named groups become captures for later criteria in the
    /// same rule.
    PathMatches(Regex),
    /// A header is present with this exact value (name compared case-insensitively).
    Header {
        /// The header name.
        name: String,
        /// The required value.
        value: String,
    },
    /// Something about the authenticated subject.
    Subject(SubjectCheck),
}

/// A condition on who is asking.
#[derive(Debug, Clone)]
pub enum SubjectCheck {
    /// Authenticated as exactly this subject.
    Is(String),
    /// A member of this group.
    InGroup(String),
    /// Holding this role.
    HasRole(String),
    /// Equal to a named capture bound earlier in the SAME rule.
    ///
    /// An unbound name never matches. That is deliberate and it is the safe direction: a
    /// typo in a capture name, or a rule reordered so the pattern that bound it no longer
    /// runs first, must refuse rather than compare the subject against nothing and admit.
    EqualsCapture(String),
    /// Authenticated at all, as anyone.
    Authenticated,
    /// Not authenticated.
    Anonymous,
}

/// One rule: a name for tracing, the criteria that must all hold, and what to do.
#[derive(Debug, Clone)]
pub struct Rule {
    /// Operator-facing name, reported in the decision so a denial can be traced to a line.
    pub name: String,
    /// Every criterion must hold. An empty list matches everything, which is how a
    /// catch-all is written.
    pub criteria: Vec<Criterion>,
    /// What this rule decides when it matches.
    pub action: Action,
}

/// What the engine was told about a request.
#[derive(Debug, Clone, Default)]
pub struct RequestFacts {
    /// The request method.
    pub method: String,
    /// The host, without port.
    pub host: String,
    /// The request path.
    pub path: String,
    /// Headers, lowercased names.
    pub headers: HashMap<String, String>,
    /// The authenticated subject, absent when the request is anonymous.
    pub subject: Option<String>,
    /// The subject's groups.
    pub groups: Vec<String>,
    /// The subject's roles.
    pub roles: Vec<String>,
}

/// The engine's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// What to do.
    pub action: Action,
    /// The rule that decided, or `None` when nothing matched.
    ///
    /// This is what answers "why was this denied": an operator reading a trace sees the rule
    /// by name, and a `None` tells them the request fell off the end rather than hitting a
    /// deny they wrote.
    pub matched: Option<String>,
}

impl Decision {
    /// The answer when no rule matched: deny, attributed to nothing.
    #[must_use]
    pub fn no_match() -> Self {
        Self {
            action: Action::Deny,
            matched: None,
        }
    }
}

/// An ordered rule set.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    /// Build a rule set from rules in evaluation order.
    #[must_use]
    pub fn new(rules: Vec<Rule>) -> Self {
        Self { rules }
    }

    /// The rules, in evaluation order.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Decide `facts` against the set: the first rule whose criteria all hold.
    #[must_use]
    pub fn decide(&self, facts: &RequestFacts) -> Decision {
        for rule in &self.rules {
            // Captures are per-rule: a fresh map each time, so one rule can never read what
            // another rule's pattern bound.
            let mut captures: HashMap<String, String> = HashMap::new();
            if rule
                .criteria
                .iter()
                .all(|criterion| matches(criterion, facts, &mut captures))
            {
                return Decision {
                    action: rule.action.clone(),
                    matched: Some(rule.name.clone()),
                };
            }
        }
        Decision::no_match()
    }
}

/// Whether one criterion holds, binding any captures it produces.
///
/// `all` short-circuits, so a criterion after a failing one does not run. That is what makes
/// the capture ordering meaningful: a subject check referring to a capture only ever sees a
/// pattern that already matched.
fn matches(
    criterion: &Criterion,
    facts: &RequestFacts,
    captures: &mut HashMap<String, String>,
) -> bool {
    match criterion {
        Criterion::Method(allowed) => allowed
            .iter()
            .any(|method| method.eq_ignore_ascii_case(&facts.method)),
        Criterion::Host(host) => host.eq_ignore_ascii_case(&facts.host),
        Criterion::PathPrefix(prefix) => facts.path.starts_with(prefix.as_str()),
        Criterion::PathMatches(pattern) => match pattern.captures(&facts.path) {
            Some(found) => {
                for name in pattern.capture_names().flatten() {
                    if let Some(value) = found.name(name) {
                        captures.insert(name.to_owned(), value.as_str().to_owned());
                    }
                }
                true
            }
            None => false,
        },
        Criterion::Header { name, value } => facts
            .headers
            .get(&name.to_ascii_lowercase())
            .is_some_and(|actual| actual == value),
        Criterion::Subject(check) => subject_matches(check, facts, captures),
    }
}

fn subject_matches(
    check: &SubjectCheck,
    facts: &RequestFacts,
    captures: &HashMap<String, String>,
) -> bool {
    match check {
        SubjectCheck::Is(subject) => facts.subject.as_deref() == Some(subject.as_str()),
        SubjectCheck::InGroup(group) => facts.groups.iter().any(|held| held == group),
        SubjectCheck::HasRole(role) => facts.roles.iter().any(|held| held == role),
        SubjectCheck::EqualsCapture(name) => match (captures.get(name), facts.subject.as_deref()) {
            // Both must be present. An unbound capture does NOT match an absent subject:
            // `None == None` would admit an anonymous request against a typo'd capture name.
            (Some(expected), Some(subject)) => expected == subject,
            _ => false,
        },
        SubjectCheck::Authenticated => facts.subject.is_some(),
        SubjectCheck::Anonymous => facts.subject.is_none(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> RequestFacts {
        RequestFacts {
            method: "GET".to_owned(),
            host: "app.example.com".to_owned(),
            path: "/".to_owned(),
            ..RequestFacts::default()
        }
    }

    fn rule(name: &str, criteria: Vec<Criterion>, action: Action) -> Rule {
        Rule {
            name: name.to_owned(),
            criteria,
            action,
        }
    }

    fn allow(name: &str, criteria: Vec<Criterion>) -> Rule {
        rule(name, criteria, Action::Allow)
    }

    fn deny(name: &str, criteria: Vec<Criterion>) -> Rule {
        rule(name, criteria, Action::Deny)
    }

    /// THE CORPUS criterion 3 asks for: one table over every criterion type, each row a
    /// request and the rule it must select.
    ///
    /// Table-driven rather than one test per criterion, because the property under test is
    /// that they COMPOSE under first-match, and a per-criterion test cannot see composition.
    #[test]
    fn the_corpus_selects_the_expected_rule_for_every_criterion_type() {
        let set = RuleSet::new(vec![
            deny(
                "block-admin-from-outside",
                vec![
                    Criterion::PathPrefix("/admin".to_owned()),
                    Criterion::Subject(SubjectCheck::Anonymous),
                ],
            ),
            allow(
                "admin-for-admins",
                vec![
                    Criterion::PathPrefix("/admin".to_owned()),
                    Criterion::Subject(SubjectCheck::HasRole("admin".to_owned())),
                ],
            ),
            allow(
                "own-record",
                vec![
                    Criterion::PathMatches(
                        Regex::new(r"^/users/(?P<uid>[^/]+)$").expect("pattern"),
                    ),
                    Criterion::Subject(SubjectCheck::EqualsCapture("uid".to_owned())),
                ],
            ),
            allow(
                "team-area",
                vec![
                    Criterion::PathPrefix("/team".to_owned()),
                    Criterion::Subject(SubjectCheck::InGroup("engineering".to_owned())),
                ],
            ),
            allow(
                "internal-host-only",
                vec![Criterion::Host("internal.example.com".to_owned())],
            ),
            allow(
                "service-header",
                vec![Criterion::Header {
                    name: "X-Service".to_owned(),
                    value: "billing".to_owned(),
                }],
            ),
            allow(
                "read-only-public",
                vec![
                    Criterion::Method(vec!["GET".to_owned(), "HEAD".to_owned()]),
                    Criterion::PathPrefix("/public".to_owned()),
                ],
            ),
        ]);

        struct Case {
            name: &'static str,
            facts: RequestFacts,
            expect: Option<&'static str>,
            action: Action,
        }

        let cases = vec![
            Case {
                name: "anonymous at /admin hits the deny above the allow",
                facts: RequestFacts {
                    path: "/admin/users".to_owned(),
                    ..facts()
                },
                expect: Some("block-admin-from-outside"),
                action: Action::Deny,
            },
            Case {
                name: "an admin reaches /admin through the rule below it",
                facts: RequestFacts {
                    path: "/admin/users".to_owned(),
                    subject: Some("usr_root".to_owned()),
                    roles: vec!["admin".to_owned()],
                    ..facts()
                },
                expect: Some("admin-for-admins"),
                action: Action::Allow,
            },
            Case {
                name: "a capture binds the subject to its own record",
                facts: RequestFacts {
                    path: "/users/alice".to_owned(),
                    subject: Some("alice".to_owned()),
                    ..facts()
                },
                expect: Some("own-record"),
                action: Action::Allow,
            },
            Case {
                name: "the same rule refuses somebody else's record",
                facts: RequestFacts {
                    path: "/users/alice".to_owned(),
                    subject: Some("bob".to_owned()),
                    ..facts()
                },
                expect: None,
                action: Action::Deny,
            },
            Case {
                name: "group membership opens the team area",
                facts: RequestFacts {
                    path: "/team/roadmap".to_owned(),
                    subject: Some("bob".to_owned()),
                    groups: vec!["engineering".to_owned()],
                    ..facts()
                },
                expect: Some("team-area"),
                action: Action::Allow,
            },
            Case {
                name: "the host criterion matches on its own",
                facts: RequestFacts {
                    host: "internal.example.com".to_owned(),
                    path: "/anything".to_owned(),
                    ..facts()
                },
                expect: Some("internal-host-only"),
                action: Action::Allow,
            },
            Case {
                name: "a header criterion matches on its own",
                facts: {
                    let mut f = RequestFacts {
                        path: "/anything".to_owned(),
                        ..facts()
                    };
                    f.headers
                        .insert("x-service".to_owned(), "billing".to_owned());
                    f
                },
                expect: Some("service-header"),
                action: Action::Allow,
            },
            Case {
                name: "GET /public is read-only-public",
                facts: RequestFacts {
                    path: "/public/logo.png".to_owned(),
                    ..facts()
                },
                expect: Some("read-only-public"),
                action: Action::Allow,
            },
            Case {
                name: "POST /public matches no rule and is denied",
                facts: RequestFacts {
                    method: "POST".to_owned(),
                    path: "/public/logo.png".to_owned(),
                    ..facts()
                },
                expect: None,
                action: Action::Deny,
            },
            Case {
                name: "a path nothing covers falls off the end",
                facts: RequestFacts {
                    path: "/unmapped".to_owned(),
                    ..facts()
                },
                expect: None,
                action: Action::Deny,
            },
        ];

        for case in cases {
            let decision = set.decide(&case.facts);
            assert_eq!(
                decision.matched.as_deref(),
                case.expect,
                "{}: wrong rule selected",
                case.name
            );
            assert_eq!(decision.action, case.action, "{}: wrong action", case.name);
        }
    }

    /// FIRST MATCH, not best match: the narrow exception ABOVE a broad deny wins, and moving
    /// it below reverses the answer. Order is the operator's tool, so it has to bite.
    #[test]
    fn order_decides_and_reordering_reverses_the_answer() {
        let exception = allow(
            "support-exception",
            vec![
                Criterion::PathPrefix("/admin".to_owned()),
                Criterion::Subject(SubjectCheck::HasRole("support".to_owned())),
            ],
        );
        let broad = deny("no-admin", vec![Criterion::PathPrefix("/admin".to_owned())]);
        let request = RequestFacts {
            path: "/admin/tickets".to_owned(),
            subject: Some("usr_1".to_owned()),
            roles: vec!["support".to_owned()],
            ..facts()
        };

        let exception_first = RuleSet::new(vec![exception.clone(), broad.clone()]);
        assert_eq!(
            exception_first.decide(&request),
            Decision {
                action: Action::Allow,
                matched: Some("support-exception".to_owned())
            }
        );

        let broad_first = RuleSet::new(vec![broad, exception]);
        assert_eq!(
            broad_first.decide(&request),
            Decision {
                action: Action::Deny,
                matched: Some("no-admin".to_owned())
            },
            "the same rules in the other order must reach the other answer"
        );
    }

    /// AN EMPTY RULE SET DENIES. The fall-through is the safe direction: a rule engine whose
    /// default admits is one forgotten rule away from an open door, and it fails silently.
    #[test]
    fn nothing_configured_denies_rather_than_admits() {
        let decision = RuleSet::default().decide(&facts());
        assert_eq!(decision.action, Action::Deny);
        assert_eq!(decision.matched, None, "and it is attributed to no rule");
    }

    /// A capture bound by one rule must not be visible to another.
    ///
    /// Otherwise moving a rule -- the operation this engine's ordering invites -- would
    /// change the meaning of a rule nobody touched.
    #[test]
    fn a_capture_does_not_leak_into_a_later_rule() {
        let set = RuleSet::new(vec![
            // Binds `uid`, then fails on the subject, so it does not match.
            allow(
                "binds-then-fails",
                vec![
                    Criterion::PathMatches(
                        Regex::new(r"^/users/(?P<uid>[^/]+)$").expect("pattern"),
                    ),
                    Criterion::Subject(SubjectCheck::Is("nobody".to_owned())),
                ],
            ),
            // Refers to `uid` without binding it. Must NOT see the previous rule's capture.
            allow(
                "reads-unbound-capture",
                vec![Criterion::Subject(SubjectCheck::EqualsCapture(
                    "uid".to_owned(),
                ))],
            ),
        ]);

        let decision = set.decide(&RequestFacts {
            path: "/users/alice".to_owned(),
            subject: Some("alice".to_owned()),
            ..facts()
        });
        assert_eq!(
            decision,
            Decision {
                action: Action::Deny,
                matched: None
            },
            "the second rule must not inherit `uid` from the first"
        );
    }

    /// An unbound capture never matches, including against an anonymous request.
    ///
    /// `None == None` would be the natural implementation and it admits: a typo'd capture
    /// name would compare nothing to nothing and open the rule to everyone unauthenticated.
    #[test]
    fn an_unbound_capture_refuses_even_an_anonymous_request() {
        let set = RuleSet::new(vec![allow(
            "typo",
            vec![
                Criterion::PathPrefix("/x".to_owned()),
                Criterion::Subject(SubjectCheck::EqualsCapture("nonexistent".to_owned())),
            ],
        )]);

        for subject in [None, Some("alice".to_owned())] {
            let decision = set.decide(&RequestFacts {
                path: "/x/y".to_owned(),
                subject,
                ..facts()
            });
            assert_eq!(
                decision,
                Decision {
                    action: Action::Deny,
                    matched: None
                }
            );
        }
    }

    /// Step-up is a third answer, not a flavour of deny: the caller can act on it.
    #[test]
    fn step_up_is_distinct_from_deny_and_carries_its_acr() {
        let set = RuleSet::new(vec![rule(
            "payments-need-mfa",
            vec![Criterion::PathPrefix("/payments".to_owned())],
            Action::StepUp {
                acr: "mfa".to_owned(),
            },
        )]);
        let decision = set.decide(&RequestFacts {
            path: "/payments/new".to_owned(),
            ..facts()
        });
        assert_eq!(
            decision.action,
            Action::StepUp {
                acr: "mfa".to_owned()
            }
        );
        assert_ne!(decision.action, Action::Deny);
    }

    /// Method and host compare case-insensitively; a header NAME does too, its value does not.
    #[test]
    fn case_sensitivity_follows_the_wire_rules() {
        let set = RuleSet::new(vec![allow(
            "mixed",
            vec![
                Criterion::Method(vec!["get".to_owned()]),
                Criterion::Host("APP.example.com".to_owned()),
                Criterion::Header {
                    name: "X-Service".to_owned(),
                    value: "billing".to_owned(),
                },
            ],
        )]);
        let mut request = RequestFacts {
            method: "GET".to_owned(),
            ..facts()
        };
        request
            .headers
            .insert("x-service".to_owned(), "billing".to_owned());
        assert_eq!(set.decide(&request).matched.as_deref(), Some("mixed"));

        // The VALUE is compared exactly: a header value is data, not a token.
        let mut wrong_case = request.clone();
        wrong_case
            .headers
            .insert("x-service".to_owned(), "Billing".to_owned());
        assert_eq!(
            set.decide(&wrong_case),
            Decision {
                action: Action::Deny,
                matched: None
            }
        );
    }
}
