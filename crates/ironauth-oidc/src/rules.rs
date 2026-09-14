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
    ///
    /// An EMPTY list matches nothing, since no method is a member of it. That is the safe
    /// reading, and it differs from a rule with no criteria at all, which matches
    /// everything.
    Method(Vec<String>),
    /// The request host equals this, case-insensitively.
    Host(String),
    /// The path lies under this prefix, on a SEGMENT boundary.
    ///
    /// `/public` matches `/public` and `/public/logo.png`, and does NOT match
    /// `/publicsecrets/db.sql`. A raw string prefix would admit the last one, which is the
    /// admitting direction of a mistake.
    ///
    /// An EMPTY prefix matches nothing. A rule with no path constraint is written by
    /// omitting this criterion, so an empty prefix is a configuration error, and reading it
    /// as a wildcard would turn one stray empty string into a rule matching every request.
    PathPrefix(String),
    /// The pattern matches the WHOLE path; named groups become captures for later criteria
    /// in the same rule.
    ///
    /// Anchoring is NOT the caller's job. A pattern is required to span the entire path
    /// whether or not it was written with `^` and `$`, because the substring reading is a
    /// privilege escalation: `/users/(?P<uid>[^/]+)` also occurs inside
    /// `/admin/users/alice`, so a rule meant to scope a user to their own record would
    /// instead admit them to the admin area, with the capture binding to their own name so
    /// the subject check passes.
    PathMatches(Regex),
    /// A header is present with this exact value.
    ///
    /// The NAME is compared case-insensitively on both sides, so it does not matter how the
    /// caller spelled the key. The VALUE is compared exactly: a header value is data, not a
    /// token.
    Header {
        /// The header name.
        name: String,
        /// The required value.
        value: String,
    },
    /// Something about the authenticated subject.
    ///
    /// Every variant requires a subject to be present before any claim about it can hold,
    /// including the group and role checks. See [`SubjectCheck`].
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

impl RequestFacts {
    /// The subject, but only when the caller actually established one.
    ///
    /// An EMPTY subject is not a subject. `Some(String::new())` is what an unset field
    /// deserialises to, what a proxy header that arrived blank produces, and what a
    /// `Default`-constructed `RequestFacts` carries if someone fills it in partially --
    /// and treating it as authenticated makes `SubjectCheck::Authenticated` admit a
    /// request nobody identified.
    ///
    /// Every subject check reads through here, so the "is there a subject at all" question
    /// is answered in ONE place rather than once per arm, where an arm can forget to ask.
    fn authenticated_subject(&self) -> Option<&str> {
        self.subject
            .as_deref()
            .filter(|subject| !subject.is_empty())
    }
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
        Criterion::PathPrefix(prefix) => path_has_prefix(&facts.path, prefix),
        Criterion::PathMatches(pattern) => match pattern.captures(&facts.path) {
            Some(found) => {
                // WHOLE-PATH match, whatever the caller wrote. `Regex::captures` finds a
                // SUBSTRING, so an unanchored pattern is a privilege escalation waiting to
                // happen: `/users/(?P<uid>[^/]+)` -- the shape this engine's own capture
                // example uses -- also matches inside `/admin/users/alice`, handing a user
                // scoped to their own record a rule that admits them to the admin area.
                //
                // Requiring the match to span the path makes an unanchored pattern behave
                // like an anchored one rather than like a wildcard, which is the safe
                // direction and costs an already-anchored pattern nothing.
                let whole = found.get(0).expect("capture group 0 always exists");
                if whole.start() != 0 || whole.end() != facts.path.len() {
                    return false;
                }
                for name in pattern.capture_names().flatten() {
                    if let Some(value) = found.name(name) {
                        captures.insert(name.to_owned(), value.as_str().to_owned());
                    }
                }
                true
            }
            None => false,
        },
        // Case-insensitive on BOTH sides. Lowercasing only the rule side made correctness
        // depend on a caller obligation stated in a doc comment, with no constructor to
        // establish it -- and the failure is silent and OPEN: a header spelled
        // `X-Internal` by the caller never matches a rule written to DENY on it, so the
        // request falls through to whatever admits next.
        Criterion::Header { name, value } => {
            facts.headers.iter().any(|(actual_name, actual_value)| {
                actual_name.eq_ignore_ascii_case(name) && actual_value == value
            })
        }
        Criterion::Subject(check) => subject_matches(check, facts, captures),
    }
}

fn subject_matches(
    check: &SubjectCheck,
    facts: &RequestFacts,
    captures: &HashMap<String, String>,
) -> bool {
    // EVERY arm reads the subject through this, so a claim is never trusted without one.
    let subject = facts.authenticated_subject();
    match check {
        SubjectCheck::Is(expected) => subject == Some(expected.as_str()),
        // A group or role is a claim ABOUT a subject, so it cannot hold without one.
        // Reading `facts.groups` alone let an identity with `subject: None` and
        // `roles: ["admin"]` satisfy an admin rule -- and on a surface that answers before
        // authentication, those claims are by definition not yet verified.
        SubjectCheck::InGroup(group) => {
            subject.is_some() && facts.groups.iter().any(|held| held == group)
        }
        SubjectCheck::HasRole(role) => {
            subject.is_some() && facts.roles.iter().any(|held| held == role)
        }
        SubjectCheck::EqualsCapture(name) => match (captures.get(name), subject) {
            // Both must be present. An unbound capture does NOT match an absent subject:
            // `None == None` would admit an anonymous request against a typo'd capture name.
            (Some(expected), Some(subject)) => expected == subject,
            _ => false,
        },
        SubjectCheck::Authenticated => subject.is_some(),
        SubjectCheck::Anonymous => subject.is_none(),
    }
}

/// Whether `path` lies under `prefix`, on a SEGMENT boundary.
///
/// A raw `starts_with` is the obvious implementation and it over-matches in the admitting
/// direction: a rule allowing `/public` also admits `/publicsecrets/db.sql`, because the
/// string prefix does not care that the segment continues.
///
/// An EMPTY prefix matches nothing rather than everything. A rule with no path constraint
/// is written by omitting the criterion, so an empty prefix is a configuration error, and
/// the safe reading of a configuration error on a pre-auth surface is to refuse. Treating
/// it as a wildcard would turn one stray empty string into a rule that matches every
/// request.
fn path_has_prefix(path: &str, prefix: &str) -> bool {
    let trimmed = prefix.trim_end_matches('/');
    if trimmed.is_empty() {
        return false;
    }
    if !path.starts_with(trimmed) {
        return false;
    }
    // Either an exact hit, or the next character starts a new segment.
    matches!(path.as_bytes().get(trimmed.len()), None | Some(b'/'))
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

    /// One row of the corpus: a request, and the rule it must select.
    ///
    /// Declared at module level rather than inside the test, so the test body stays a loop
    /// and clippy's items-after-statements has nothing to object to.
    struct Case {
        name: &'static str,
        facts: RequestFacts,
        expect: Option<&'static str>,
        action: Action,
    }

    /// The rule set the corpus runs against: one rule per criterion type, ordered so that
    /// the narrow exceptions sit above the broad denials.
    fn corpus_rules() -> RuleSet {
        RuleSet::new(vec![
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
        ])
    }

    /// The rows. Every `Criterion` variant appears, and every `SubjectCheck` variant that
    /// the rule set above can exercise.
    ///
    /// Split in two only to stay under clippy's function-length limit; the test runs both.
    fn corpus_cases() -> Vec<Case> {
        let mut cases = corpus_cases_subject();
        cases.extend(corpus_cases_request());
        cases
    }

    /// The rows whose selection turns on the SUBJECT: roles, captures, groups.
    fn corpus_cases_subject() -> Vec<Case> {
        vec![
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
        ]
    }

    /// The rows whose selection turns on the REQUEST: host, header, method, path.
    fn corpus_cases_request() -> Vec<Case> {
        vec![
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
        ]
    }

    /// THE CORPUS criterion 3 asks for: one table over every criterion type, each row a
    /// request and the rule it must select.
    ///
    /// Table-driven rather than one test per criterion, because the property under test is
    /// that they COMPOSE under first-match, and a per-criterion test cannot see composition.
    #[test]
    fn the_corpus_selects_the_expected_rule_for_every_criterion_type() {
        let set = corpus_rules();
        for case in corpus_cases() {
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

    // -----------------------------------------------------------------------
    // The fail-open paths. Every test below was written against a defect an
    // adversarial review reached with a working probe, and every one of them
    // ended in Allow on a surface that answers before authentication.
    // -----------------------------------------------------------------------

    /// A HEADER THE CALLER SPELLED IN MIXED CASE MUST STILL MATCH A DENY.
    ///
    /// The engine lowercased only the rule side, leaving the facts side a caller obligation
    /// stated in a doc comment with no constructor to establish it. The failure is silent
    /// and admits: a deny rule written on `X-Internal` never fires, and the request falls
    /// through to whatever admits next.
    #[test]
    fn a_mixed_case_header_from_the_caller_still_reaches_its_rule() {
        let set = RuleSet::new(vec![
            deny(
                "block-internal-marker",
                vec![Criterion::Header {
                    name: "X-Internal".to_owned(),
                    value: "1".to_owned(),
                }],
            ),
            allow("everything-else", vec![]),
        ]);

        for spelling in ["x-internal", "X-Internal", "X-INTERNAL", "x-InTeRnAl"] {
            let mut request = facts();
            request.headers.insert(spelling.to_owned(), "1".to_owned());
            assert_eq!(
                set.decide(&request).matched.as_deref(),
                Some("block-internal-marker"),
                "a header spelled {spelling} must still reach the rule that denies on it"
            );
        }
    }

    /// A PREFIX MATCHES ON A SEGMENT BOUNDARY, not on raw bytes.
    ///
    /// `"/publicsecrets/db.sql".starts_with("/public")` is true, so a rule opening `/public`
    /// also opened a sibling path that merely shares its first seven characters.
    #[test]
    fn a_path_prefix_does_not_leak_into_a_longer_sibling_segment() {
        let set = RuleSet::new(vec![allow(
            "public",
            vec![Criterion::PathPrefix("/public".to_owned())],
        )]);

        for allowed in ["/public", "/public/", "/public/logo.png", "/public/a/b"] {
            let request = RequestFacts {
                path: allowed.to_owned(),
                ..facts()
            };
            assert_eq!(
                set.decide(&request).matched.as_deref(),
                Some("public"),
                "{allowed} is under the prefix"
            );
        }
        for refused in [
            "/publicsecrets/db.sql",
            "/publicity",
            "/public-internal",
            "/pub",
        ] {
            let request = RequestFacts {
                path: refused.to_owned(),
                ..facts()
            };
            assert_eq!(
                set.decide(&request),
                Decision {
                    action: Action::Deny,
                    matched: None
                },
                "{refused} only shares a string prefix and must not match"
            );
        }
    }

    /// AN EMPTY PREFIX MATCHES NOTHING, not everything.
    ///
    /// A rule with no path constraint is written by omitting the criterion, so an empty
    /// prefix is a configuration error. Read as a wildcard it turns one stray empty string
    /// into a rule matching every request, which is the worst available reading of a typo.
    #[test]
    fn an_empty_path_prefix_is_not_a_wildcard() {
        let set = RuleSet::new(vec![allow(
            "oops",
            vec![Criterion::PathPrefix(String::new())],
        )]);
        for path in ["/admin/keys", "/", "/anything"] {
            let request = RequestFacts {
                path: path.to_owned(),
                ..facts()
            };
            assert_eq!(
                set.decide(&request),
                Decision {
                    action: Action::Deny,
                    matched: None
                },
                "an empty prefix must not admit {path}"
            );
        }
    }

    /// AN UNANCHORED PATTERN MATCHES THE WHOLE PATH OR NOTHING.
    ///
    /// `Regex::captures` finds a SUBSTRING. The engine's own capture example,
    /// `/users/(?P<uid>[^/]+)`, also matches inside `/admin/users/alice` -- so without
    /// whole-path matching the rule scoping alice to her own record instead walks her into
    /// the admin area, with the capture binding to her own name so the subject check passes.
    #[test]
    fn an_unanchored_pattern_cannot_match_inside_a_longer_path() {
        let set = RuleSet::new(vec![allow(
            "own-record",
            vec![
                // Deliberately NOT anchored: this is the shape being defended against.
                Criterion::PathMatches(Regex::new(r"/users/(?P<uid>[^/]+)").expect("pattern")),
                Criterion::Subject(SubjectCheck::EqualsCapture("uid".to_owned())),
            ],
        )]);

        let escalation = RequestFacts {
            path: "/admin/users/alice".to_owned(),
            subject: Some("alice".to_owned()),
            ..facts()
        };
        assert_eq!(
            set.decide(&escalation),
            Decision {
                action: Action::Deny,
                matched: None
            },
            "an unanchored pattern must not reach inside a longer path"
        );

        // And the intended path still works, so this is not simply breaking the feature.
        let intended = RequestFacts {
            path: "/users/alice".to_owned(),
            subject: Some("alice".to_owned()),
            ..facts()
        };
        assert_eq!(set.decide(&intended).matched.as_deref(), Some("own-record"));
    }

    /// A ROLE OR GROUP IS A CLAIM ABOUT A SUBJECT AND CANNOT HOLD WITHOUT ONE.
    ///
    /// `RequestFacts` derives `Default` and every field is `pub`, so a caller can present
    /// `roles: ["admin"]` with `subject: None`. Neither check consulted the subject, so
    /// that identity satisfied an admin rule on a pre-auth surface, where the claims are by
    /// definition not yet verified.
    #[test]
    fn roles_and_groups_do_not_hold_without_a_subject() {
        let set = RuleSet::new(vec![
            allow(
                "admins",
                vec![
                    Criterion::PathPrefix("/admin".to_owned()),
                    Criterion::Subject(SubjectCheck::HasRole("admin".to_owned())),
                ],
            ),
            allow(
                "engineers",
                vec![
                    Criterion::PathPrefix("/team".to_owned()),
                    Criterion::Subject(SubjectCheck::InGroup("engineering".to_owned())),
                ],
            ),
        ]);

        let unidentified_admin = RequestFacts {
            path: "/admin/keys".to_owned(),
            subject: None,
            roles: vec!["admin".to_owned()],
            ..facts()
        };
        assert_eq!(
            set.decide(&unidentified_admin),
            Decision {
                action: Action::Deny,
                matched: None
            },
            "a role claim without a subject must not admit"
        );

        let unidentified_engineer = RequestFacts {
            path: "/team/roadmap".to_owned(),
            subject: None,
            groups: vec!["engineering".to_owned()],
            ..facts()
        };
        assert_eq!(
            set.decide(&unidentified_engineer),
            Decision {
                action: Action::Deny,
                matched: None
            },
            "a group claim without a subject must not admit"
        );

        // With a subject, both admit: the fix constrains the claim, it does not delete it.
        let identified = RequestFacts {
            path: "/admin/keys".to_owned(),
            subject: Some("usr_1".to_owned()),
            roles: vec!["admin".to_owned()],
            ..facts()
        };
        assert_eq!(set.decide(&identified).matched.as_deref(), Some("admins"));
    }

    /// AN EMPTY SUBJECT IS NOT A SUBJECT.
    ///
    /// `Some(String::new())` is what a blank proxy header produces and what a partially
    /// filled `RequestFacts` carries. Counting it as authenticated admits a request nobody
    /// identified; counting it as anonymous is both safe and true.
    #[test]
    fn an_empty_subject_is_anonymous_not_authenticated() {
        let set = RuleSet::new(vec![allow(
            "signed-in",
            vec![Criterion::Subject(SubjectCheck::Authenticated)],
        )]);
        let blank = RequestFacts {
            subject: Some(String::new()),
            ..facts()
        };
        assert_eq!(
            set.decide(&blank),
            Decision {
                action: Action::Deny,
                matched: None
            },
            "an empty subject must not satisfy Authenticated"
        );

        let anonymous_set = RuleSet::new(vec![allow(
            "not-signed-in",
            vec![Criterion::Subject(SubjectCheck::Anonymous)],
        )]);
        assert_eq!(
            anonymous_set.decide(&blank).matched.as_deref(),
            Some("not-signed-in"),
            "and it must read as anonymous, so the two remain a partition"
        );
    }

    /// `Authenticated` and `Anonymous` PARTITION every input: exactly one holds.
    #[test]
    fn authenticated_and_anonymous_partition_every_subject() {
        let authed = RuleSet::new(vec![allow(
            "a",
            vec![Criterion::Subject(SubjectCheck::Authenticated)],
        )]);
        let anon = RuleSet::new(vec![allow(
            "b",
            vec![Criterion::Subject(SubjectCheck::Anonymous)],
        )]);

        for subject in [None, Some(String::new()), Some("alice".to_owned())] {
            let request = RequestFacts {
                subject: subject.clone(),
                ..facts()
            };
            let is_authed = authed.decide(&request).matched.is_some();
            let is_anon = anon.decide(&request).matched.is_some();
            assert!(
                is_authed != is_anon,
                "exactly one of Authenticated/Anonymous must hold for {subject:?}"
            );
        }
    }

    /// `SubjectCheck::Is` in BOTH directions. It appeared once in the suite, as
    /// `Is("nobody")` against subject `alice` -- only ever the false direction, so replacing
    /// the whole arm with `false` cost nothing.
    #[test]
    fn subject_is_matches_the_named_subject_and_only_that_one() {
        let set = RuleSet::new(vec![allow(
            "just-alice",
            vec![Criterion::Subject(SubjectCheck::Is("alice".to_owned()))],
        )]);

        let alice = RequestFacts {
            subject: Some("alice".to_owned()),
            ..facts()
        };
        assert_eq!(set.decide(&alice).matched.as_deref(), Some("just-alice"));

        for other in [None, Some("bob".to_owned()), Some("alice2".to_owned())] {
            let request = RequestFacts {
                subject: other.clone(),
                ..facts()
            };
            assert_eq!(
                set.decide(&request),
                Decision {
                    action: Action::Deny,
                    matched: None
                },
                "{other:?} is not alice"
            );
        }
    }

    /// AN EMPTY METHOD LIST MATCHES NOTHING, and a rule with NO criteria matches everything.
    ///
    /// The two look similar and mean opposite things, so both are pinned. The catch-all is
    /// the documented behaviour of an empty `criteria` vec and it is what makes a trailing
    /// default rule expressible; an empty `Method` list is a constraint no method satisfies.
    #[test]
    fn an_empty_method_list_matches_nothing_but_no_criteria_matches_everything() {
        let narrow = RuleSet::new(vec![allow("impossible", vec![Criterion::Method(vec![])])]);
        assert_eq!(
            narrow.decide(&facts()),
            Decision {
                action: Action::Deny,
                matched: None
            },
            "no method is a member of the empty list"
        );

        let catch_all = RuleSet::new(vec![allow("everything", vec![])]);
        for path in ["/", "/admin/keys", "/anything"] {
            let request = RequestFacts {
                path: path.to_owned(),
                ..facts()
            };
            assert_eq!(
                catch_all.decide(&request).matched.as_deref(),
                Some("everything"),
                "a rule with no criteria is the documented catch-all"
            );
        }
    }
}
