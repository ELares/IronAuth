// SPDX-License-Identifier: MIT OR Apache-2.0

//! Trusted-header SSO for a forward-auth surface (issue #154 criterion 2).
//!
//! A reverse proxy asks this surface whether to admit a request. On an admission the upstream
//! application is told WHO the caller is through headers it trusts: `Remote-User`,
//! `Remote-Groups`, `Remote-Email`, `Remote-Name`. The application reads them and believes
//! them, because by construction they can only have come from the authenticator.
//!
//! That last clause is the entire security property, and it has two halves that fail in
//! opposite directions:
//!
//! - **Nothing reaches the upstream unless the decision was an allow.** A denial that still
//!   emitted `Remote-User` would hand the application an identity for a request it was told
//!   to refuse.
//! - **Nothing the CLIENT sent under those names survives.** A caller who sets `Remote-User:
//!   admin` and reaches an upstream that trusts the header has authenticated as anyone, with
//!   no bug anywhere in the authenticator. The header is trusted BECAUSE it is supposed to be
//!   unforgeable, so forging it is the whole attack.
//!
//! # Why stripping happens before evaluation, not after
//!
//! It would be enough for the SECOND property to strip on the way out. It is not enough for
//! correctness: the rules engine reads request headers, so a client-supplied `Remote-Groups:
//! admins` could satisfy a rule written about the header the upstream trusts. Stripping on
//! input means a rule can never be evaluated against a value the client chose for a name the
//! system reserves.

use crate::rules::{Action, Decision, RequestFacts, RuleSet};

/// The header names an upstream application trusts, lowercased.
///
/// Reserved: a client can never contribute a value under any of these names, whatever the
/// case, and a rule is never evaluated against one it sent.
pub const TRUSTED_HEADERS: [&str; 4] = [
    "remote-user",
    "remote-groups",
    "remote-email",
    "remote-name",
];

/// Whether `name` is reserved for the authenticator, comparing case-insensitively.
#[must_use]
pub fn is_trusted_header(name: &str) -> bool {
    TRUSTED_HEADERS
        .iter()
        .any(|reserved| name.eq_ignore_ascii_case(reserved))
}

/// What the authenticator knows about the caller.
///
/// Built from the session, never from the request, which is the point.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Identity {
    /// The subject identifier.
    pub user: String,
    /// Group memberships.
    pub groups: Vec<String>,
    /// The verified email address, if the deployment has one.
    pub email: Option<String>,
    /// The display name, if the deployment has one.
    pub name: Option<String>,
}

/// What a forward-auth surface answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardAuthOutcome {
    /// The access decision.
    pub decision: Decision,
    /// Headers to add to the upstream request. EMPTY unless the decision was an allow.
    pub upstream_headers: Vec<(String, String)>,
    /// Reserved header names the client sent, which were removed.
    ///
    /// Surfaced rather than dropped silently: a client sending `Remote-User` is either a
    /// misconfigured proxy or an attempt to forge an identity, and an operator wants to know
    /// which without reproducing it.
    pub stripped: Vec<String>,
}

/// A forward-auth surface over a rule set.
pub struct ForwardAuth {
    rules: RuleSet,
}

impl ForwardAuth {
    /// Build a surface over `rules`.
    #[must_use]
    pub fn new(rules: RuleSet) -> Self {
        Self { rules }
    }

    /// The rules this surface enforces.
    #[must_use]
    pub fn rules(&self) -> &RuleSet {
        &self.rules
    }

    /// Decide `facts`, and say what the upstream should be told.
    ///
    /// `facts` is taken by value and sanitised here rather than by the caller, so there is no
    /// path that evaluates un-sanitised facts. A caller who wants to know what was removed
    /// reads [`ForwardAuthOutcome::stripped`].
    ///
    /// `identity` is what the AUTHENTICATOR established, and is the only source of the
    /// headers emitted upstream. An anonymous request can still be allowed, by a rule that
    /// does not require a subject, and then there is no identity to forward.
    #[must_use]
    pub fn evaluate(&self, facts: RequestFacts, identity: Option<&Identity>) -> ForwardAuthOutcome {
        let (facts, stripped) = strip_trusted_headers(facts);
        let decision = self.rules.decide(&facts);

        // ONLY an allow forwards anything. A step-up is not an admission: the caller has to
        // come back with a stronger authentication, and handing the upstream an identity in
        // the meantime would defeat the requirement being made.
        let upstream_headers = match (&decision.action, identity) {
            (Action::Allow, Some(identity)) => upstream_headers_for(identity),
            (Action::Allow, None) | (Action::Deny | Action::StepUp { .. }, _) => Vec::new(),
        };

        ForwardAuthOutcome {
            decision,
            upstream_headers,
            stripped,
        }
    }
}

/// Remove every reserved header the client sent, returning the sanitised facts and the names
/// that were removed.
///
/// Returns the names as the CLIENT spelled them, because that is what an operator needs in
/// order to recognise the proxy or the caller responsible.
#[must_use]
pub fn strip_trusted_headers(mut facts: RequestFacts) -> (RequestFacts, Vec<String>) {
    let mut stripped: Vec<String> = facts
        .headers
        .keys()
        .filter(|name| is_trusted_header(name))
        .cloned()
        .collect();
    // Sorted so the report is stable: `HashMap` iteration order is not, and a log line that
    // reorders itself between identical requests is one nobody can diff.
    stripped.sort_unstable();
    for name in &stripped {
        facts.headers.remove(name);
    }
    (facts, stripped)
}

/// The headers an upstream application should receive for `identity`.
///
/// Groups are comma-joined, which is the convention the trusted-header consumers expect.
/// Absent optional fields are OMITTED rather than sent empty, so an upstream can tell "no
/// email on this account" from "an empty email", which are different facts.
#[must_use]
pub fn upstream_headers_for(identity: &Identity) -> Vec<(String, String)> {
    let mut headers = vec![
        ("Remote-User".to_owned(), identity.user.clone()),
        ("Remote-Groups".to_owned(), identity.groups.join(",")),
    ];
    if let Some(email) = &identity.email {
        headers.push(("Remote-Email".to_owned(), email.clone()));
    }
    if let Some(name) = &identity.name {
        headers.push(("Remote-Name".to_owned(), name.clone()));
    }
    headers
}

/// Build request facts from a proxy's forwarded description of the original request.
///
/// A convenience for a dialect adapter: it sanitises on the way in, so a dialect cannot
/// forget to.
#[must_use]
pub fn facts_from_proxy<I>(
    method: &str,
    host: &str,
    path: &str,
    headers: I,
) -> (RequestFacts, Vec<String>)
where
    I: IntoIterator<Item = (String, String)>,
{
    strip_trusted_headers(RequestFacts {
        method: method.to_owned(),
        host: host.to_owned(),
        path: path.to_owned(),
        headers: headers.into_iter().collect(),
        ..RequestFacts::default()
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::rules::{Criterion, Rule};

    use super::*;

    fn identity() -> Identity {
        Identity {
            user: "alice".to_owned(),
            groups: vec!["engineering".to_owned(), "oncall".to_owned()],
            email: Some("alice@example.test".to_owned()),
            name: Some("Alice".to_owned()),
        }
    }

    fn rule(name: &str, criteria: Vec<Criterion>, action: Action) -> Rule {
        Rule {
            name: name.to_owned(),
            criteria,
            action,
        }
    }

    fn open() -> ForwardAuth {
        ForwardAuth::new(RuleSet::new(vec![rule("open", vec![], Action::Allow)]))
    }

    fn shut() -> ForwardAuth {
        ForwardAuth::new(RuleSet::new(vec![rule("shut", vec![], Action::Deny)]))
    }

    fn request_with(name: &str, value: &str) -> RequestFacts {
        let mut facts = RequestFacts {
            method: "GET".to_owned(),
            host: "app.example.test".to_owned(),
            path: "/".to_owned(),
            ..RequestFacts::default()
        };
        facts.headers.insert(name.to_owned(), value.to_owned());
        facts
    }

    /// A CLIENT CANNOT AUTHENTICATE ITSELF BY SENDING THE HEADER.
    ///
    /// The upstream trusts `Remote-User` because it is supposed to be unforgeable, so forging
    /// it is the whole attack. Every case-spelling is stripped, because the upstream and the
    /// proxy compare header names case-insensitively and an attacker will try the ones a
    /// naive filter misses.
    #[test]
    fn a_client_supplied_identity_header_never_survives() {
        for spelling in ["Remote-User", "remote-user", "REMOTE-USER", "ReMoTe-UsEr"] {
            let outcome = open().evaluate(request_with(spelling, "root"), None);
            assert_eq!(
                outcome.decision.action,
                Action::Allow,
                "{spelling}: precondition, this rule set admits everything"
            );
            assert!(
                !outcome
                    .upstream_headers
                    .iter()
                    .any(|(_, value)| value == "root"),
                "{spelling}: a client-sent identity must not reach the upstream"
            );
            assert_eq!(
                outcome.stripped,
                vec![spelling.to_owned()],
                "{spelling}: and the attempt is reported, spelled as the client sent it"
            );
        }
    }

    /// EVERY RESERVED NAME IS RESERVED, not only the user one.
    #[test]
    fn every_trusted_header_name_is_stripped_from_client_input() {
        for reserved in TRUSTED_HEADERS {
            let outcome = open().evaluate(request_with(reserved, "forged"), None);
            assert_eq!(
                outcome.stripped,
                vec![reserved.to_owned()],
                "{reserved} must be reserved"
            );
            assert!(outcome.upstream_headers.is_empty());
        }
    }

    /// A RULE IS NEVER EVALUATED AGAINST A RESERVED HEADER THE CLIENT SENT.
    ///
    /// This is why stripping happens on the way IN. Filtering only the response would still
    /// let a client-supplied `Remote-Groups: admins` satisfy a rule written about the header
    /// the upstream trusts, and the decision itself would be wrong.
    #[test]
    fn a_client_cannot_satisfy_a_rule_with_a_reserved_header() {
        let gated = ForwardAuth::new(RuleSet::new(vec![
            rule(
                "admins-area",
                vec![Criterion::Header {
                    name: "Remote-Groups".to_owned(),
                    value: "admins".to_owned(),
                }],
                Action::Allow,
            ),
            rule("default-deny", vec![], Action::Deny),
        ]));

        let outcome = gated.evaluate(request_with("Remote-Groups", "admins"), None);
        assert_eq!(
            outcome.decision.action,
            Action::Deny,
            "the rule must not see a value the client chose for a reserved name"
        );
        assert_eq!(outcome.decision.matched.as_deref(), Some("default-deny"));
        assert_eq!(outcome.stripped, vec!["Remote-Groups".to_owned()]);
    }

    /// A DENIAL FORWARDS NOTHING, even with a fully authenticated identity in hand.
    #[test]
    fn a_denied_request_forwards_no_identity() {
        let outcome = shut().evaluate(request_with("X-Other", "kept"), Some(&identity()));
        assert_eq!(outcome.decision.action, Action::Deny);
        assert!(
            outcome.upstream_headers.is_empty(),
            "a refusal must not hand the upstream an identity for a request it was told to refuse"
        );
    }

    /// A STEP-UP FORWARDS NOTHING EITHER. It is not an admission.
    ///
    /// The caller has to come back with stronger authentication; handing the upstream an
    /// identity in the meantime defeats the requirement being made.
    #[test]
    fn a_step_up_forwards_no_identity() {
        let stepped = ForwardAuth::new(RuleSet::new(vec![rule(
            "mfa",
            vec![],
            Action::StepUp {
                acr: "mfa".to_owned(),
            },
        )]));
        let outcome = stepped.evaluate(request_with("X-Other", "kept"), Some(&identity()));
        assert_eq!(
            outcome.decision.action,
            Action::StepUp {
                acr: "mfa".to_owned()
            }
        );
        assert!(outcome.upstream_headers.is_empty());
    }

    /// AN ADMISSION FORWARDS THE AUTHENTICATOR'S VIEW, and only that.
    #[test]
    fn an_allowed_request_forwards_the_established_identity() {
        let outcome = open().evaluate(request_with("Remote-User", "root"), Some(&identity()));
        assert_eq!(outcome.decision.action, Action::Allow);
        assert_eq!(
            outcome.upstream_headers,
            vec![
                ("Remote-User".to_owned(), "alice".to_owned()),
                ("Remote-Groups".to_owned(), "engineering,oncall".to_owned()),
                ("Remote-Email".to_owned(), "alice@example.test".to_owned()),
                ("Remote-Name".to_owned(), "Alice".to_owned()),
            ],
            "the forged `root` is gone and the session's `alice` is what the upstream sees"
        );
    }

    /// AN ANONYMOUS ADMISSION FORWARDS NOTHING.
    ///
    /// A rule can admit without requiring a subject. There is then no identity to forward,
    /// and inventing an empty one would let an upstream read `Remote-User: ` as a user.
    #[test]
    fn an_anonymous_admission_forwards_no_identity() {
        let outcome = open().evaluate(request_with("X-Other", "kept"), None);
        assert_eq!(outcome.decision.action, Action::Allow);
        assert!(outcome.upstream_headers.is_empty());
    }

    /// AN ABSENT OPTIONAL FIELD IS OMITTED, not sent empty.
    ///
    /// An upstream can then tell "no email on this account" from "an empty email", which are
    /// different facts and often route differently.
    #[test]
    fn absent_optional_fields_are_omitted_rather_than_blank() {
        let sparse = Identity {
            user: "bob".to_owned(),
            groups: Vec::new(),
            email: None,
            name: None,
        };
        let headers = upstream_headers_for(&sparse);
        let names: Vec<&str> = headers.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, vec!["Remote-User", "Remote-Groups"]);
        assert_eq!(
            headers[1].1, "",
            "no groups is an empty list, which is a real answer, unlike a missing email"
        );
    }

    /// A NON-RESERVED HEADER IS LEFT ALONE.
    ///
    /// The counterweight: stripping everything would break every rule written about an
    /// ordinary header.
    #[test]
    fn an_ordinary_header_is_not_stripped() {
        let gated = ForwardAuth::new(RuleSet::new(vec![
            rule(
                "by-service",
                vec![Criterion::Header {
                    name: "X-Service".to_owned(),
                    value: "billing".to_owned(),
                }],
                Action::Allow,
            ),
            rule("default-deny", vec![], Action::Deny),
        ]));
        let outcome = gated.evaluate(request_with("X-Service", "billing"), None);
        assert_eq!(outcome.decision.matched.as_deref(), Some("by-service"));
        assert!(outcome.stripped.is_empty());
    }

    /// THE STRIP REPORT IS STABLE, so a log line does not reorder between identical requests.
    #[test]
    fn the_strip_report_is_sorted() {
        let mut facts = request_with("Remote-User", "a");
        facts
            .headers
            .insert("Remote-Name".to_owned(), "b".to_owned());
        facts
            .headers
            .insert("Remote-Email".to_owned(), "c".to_owned());

        let first = strip_trusted_headers(facts.clone()).1;
        assert_eq!(
            first,
            vec![
                "Remote-Email".to_owned(),
                "Remote-Name".to_owned(),
                "Remote-User".to_owned()
            ]
        );
        for _ in 0..50 {
            assert_eq!(strip_trusted_headers(facts.clone()).1, first);
        }
    }

    /// THE PROXY ADAPTER SANITISES TOO, so a dialect cannot forget to.
    #[test]
    fn the_proxy_adapter_cannot_forward_a_reserved_header() {
        let mut headers = HashMap::new();
        headers.insert("remote-user".to_owned(), "root".to_owned());
        headers.insert("x-kept".to_owned(), "yes".to_owned());

        let (facts, stripped) = facts_from_proxy("GET", "app.example.test", "/", headers);
        assert_eq!(stripped, vec!["remote-user".to_owned()]);
        assert!(!facts.headers.contains_key("remote-user"));
        assert_eq!(facts.headers.get("x-kept").map(String::as_str), Some("yes"));
    }
}
