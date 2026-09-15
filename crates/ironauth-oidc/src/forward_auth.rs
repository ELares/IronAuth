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
//! - **Nothing the CLIENT sent under those names influences anything.** A caller who sets
//!   `Remote-User: admin` and reaches an upstream that trusts the header has authenticated as
//!   anyone, with no bug anywhere in the authenticator.
//!
//! # What this module enforces, and what it does not
//!
//! It enforces that IronAuth's own decision never sees a reserved header the client sent, and
//! that the headers it emits come only from the authenticator. It CANNOT delete anything from
//! the request the proxy forwards: that is the proxy's configuration, which is criterion 1's
//! work. [`ForwardAuthOutcome::must_delete`] is therefore an INSTRUCTION to the dialect
//! adapter, not a record of something already done. A dialect that sets-if-present rather
//! than delete-then-set leaves a forged header in place, and the naming here is deliberate so
//! that is hard to miss.
//!
//! # Why stripping happens before evaluation, not after
//!
//! It would be enough for the second half to strip on the way out. It is not enough for
//! correctness: the rules engine reads request headers, so a client-supplied `Remote-Groups:
//! admins` could satisfy a rule written about the header the upstream trusts. Stripping on
//! input means a rule can never be evaluated against a value the client chose for a name the
//! system reserves.

use crate::rules::{Action, Decision, RequestFacts, RuleSet};

/// The trusted headers, each paired with the identity field it carries.
///
/// ONE list, read by both the emitter and the reservation check. They were separate, and
/// nothing tied them: a fifth emitted header could be added without becoming reserved, which
/// is a silent forgery hole with no check anywhere. Deriving both from this makes that
/// impossible rather than merely unlikely.
/// How one trusted header reads its value out of an [`Identity`].
type ReadField = fn(&Identity) -> Option<String>;

const TRUSTED: [(&str, ReadField); 4] = [
    ("Remote-User", |identity| Some(identity.user.clone())),
    ("Remote-Groups", |identity| Some(identity.groups.join(","))),
    ("Remote-Email", |identity| identity.email.clone()),
    ("Remote-Name", |identity| identity.name.clone()),
];

/// The header names reserved for the authenticator, as emitted.
pub fn trusted_header_names() -> impl Iterator<Item = &'static str> {
    TRUSTED.iter().map(|(name, _)| *name)
}

/// The canonical form of a header name for the reservation check.
///
/// Lowercased, underscores folded to hyphens, surrounding whitespace removed.
///
/// # Why more than a case fold
///
/// `eq_ignore_ascii_case` on the exact name let `Remote_User` through, and a review then used
/// a rule naming `Remote_Groups` to let a client-chosen value decide a request. To any
/// `CGI`, `FastCGI`, `WSGI` or PHP upstream, `Remote_User` and `Remote-User` are the SAME variable
/// (`HTTP_REMOTE_USER`), and those self-hosted applications are exactly the class forward-auth
/// exists to protect. Leading and trailing whitespace is stripped for the same reason: a
/// parser that trims before lookup would see the reserved name.
fn canonical_header_name(name: &str) -> String {
    name.trim()
        .chars()
        .map(|c| {
            if c == '_' {
                '-'
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect()
}

/// Whether `name` is reserved for the authenticator.
#[must_use]
pub fn is_trusted_header(name: &str) -> bool {
    let canonical = canonical_header_name(name);
    trusted_header_names().any(|reserved| canonical_header_name(reserved) == canonical)
}

/// Why an identity cannot be sent to an upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// A field carries a byte that cannot appear in a header value.
    ///
    /// Carrying a carriage return or newline is request splitting: `alice\r\nRemote-Groups:
    /// admins` becomes a second header the upstream reads as authoritative.
    ControlCharacter {
        /// The field that carries it.
        field: &'static str,
    },
    /// A group name contains the separator that joins the list.
    ///
    /// One group literally named `users,admins` is byte-identical on the wire to membership
    /// in two groups. Directory-synced group display names are not charset-restricted, so
    /// `Finance, EU` is an ordinary name rather than an exotic one.
    SeparatorInGroup {
        /// The offending group.
        group: String,
    },
    /// The subject is empty, which an upstream would read as a user named nothing.
    EmptySubject,
}

/// What the authenticator knows about the caller.
///
/// Built from the session, never from the request, which is the point.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Identity {
    /// The subject identifier.
    pub user: String,
    /// Group memberships. A group name may not contain a comma; see [`IdentityError`].
    pub groups: Vec<String>,
    /// Role memberships, for rules that check roles.
    pub roles: Vec<String>,
    /// The verified email address, if the deployment has one.
    pub email: Option<String>,
    /// The display name, if the deployment has one.
    pub name: Option<String>,
}

impl Identity {
    /// Whether this identity can be serialised into headers safely.
    ///
    /// # Errors
    ///
    /// [`IdentityError`] naming the first problem found.
    pub fn validate(&self) -> Result<(), IdentityError> {
        if self.user.is_empty() {
            return Err(IdentityError::EmptySubject);
        }
        let forbidden = |value: &str| value.chars().any(char::is_control);
        if forbidden(&self.user) {
            return Err(IdentityError::ControlCharacter { field: "user" });
        }
        for group in &self.groups {
            if forbidden(group) {
                return Err(IdentityError::ControlCharacter { field: "groups" });
            }
            if group.contains(',') {
                return Err(IdentityError::SeparatorInGroup {
                    group: group.clone(),
                });
            }
        }
        for role in &self.roles {
            if forbidden(role) {
                return Err(IdentityError::ControlCharacter { field: "roles" });
            }
        }
        if self.email.as_deref().is_some_and(forbidden) {
            return Err(IdentityError::ControlCharacter { field: "email" });
        }
        if self.name.as_deref().is_some_and(forbidden) {
            return Err(IdentityError::ControlCharacter { field: "name" });
        }
        Ok(())
    }
}

/// What a forward-auth surface answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardAuthOutcome {
    /// The access decision.
    pub decision: Decision,
    /// Headers to ADD to the upstream request. Empty unless the decision was an allow.
    pub upstream_headers: Vec<(String, String)>,
    /// Header names the dialect adapter MUST DELETE from the forwarded request.
    ///
    /// An instruction, not a record. This module removed them from its own view of the
    /// request so no rule could be evaluated against one; whether the client's forged header
    /// reaches the upstream depends on the proxy, which this module does not configure.
    ///
    /// Surfaced rather than dropped silently for a second reason: a client sending
    /// `Remote-User` is either a misconfigured proxy or an attempt to forge an identity, and
    /// an operator wants to know which without reproducing it.
    pub must_delete: Vec<String>,
    /// Set when an identity was supplied that cannot be sent to an upstream.
    ///
    /// The decision is forced to [`Action::Deny`] in that case. A silently dropped header
    /// while the admission stands is worse than a refusal: the upstream would serve the
    /// request as some OTHER principal, or as none.
    pub identity_rejected: Option<IdentityError>,
}

/// A forward-auth surface over a rule set.
///
/// Holds the rules privately and exposes no accessor for them. An earlier version had one,
/// and it handed a caller holding the sanitising surface a reference that skips sanitising.
pub struct ForwardAuth {
    rules: RuleSet,
}

impl ForwardAuth {
    /// Build a surface over `rules`.
    #[must_use]
    pub fn new(rules: RuleSet) -> Self {
        Self { rules }
    }

    /// Decide `facts`, and say what the upstream should be told.
    ///
    /// `facts` is taken by value and sanitised here, so this surface cannot evaluate an
    /// unsanitised request. That is a property of THIS function, not of the crate: the rules
    /// engine's own entry points take a [`RequestFacts`] whose fields are public, so a
    /// deployment that calls them directly is not protected by anything here. Route
    /// forward-auth traffic through this function.
    ///
    /// # The principal is taken from `identity`, not from `facts`
    ///
    /// The subject, groups and roles the engine decides about are OVERWRITTEN from
    /// `identity`. They were independent inputs, and a review authorised `alice` on her group
    /// membership while telling the upstream it was serving `mallory`. There is now one
    /// principal, so the two cannot disagree.
    #[must_use]
    pub fn evaluate(&self, facts: RequestFacts, identity: Option<&Identity>) -> ForwardAuthOutcome {
        let (mut facts, must_delete) = strip_trusted_headers(facts);

        // An identity that cannot be serialised is a refusal, not a silent drop.
        if let Some(problem) = identity.and_then(|identity| identity.validate().err()) {
            return ForwardAuthOutcome {
                decision: Decision::no_match(),
                upstream_headers: Vec::new(),
                must_delete,
                identity_rejected: Some(problem),
            };
        }

        // ONE principal: what the engine decides about is what the upstream is told.
        facts.subject = identity.map(|identity| identity.user.clone());
        facts.groups = identity
            .map(|identity| identity.groups.clone())
            .unwrap_or_default();
        facts.roles = identity
            .map(|identity| identity.roles.clone())
            .unwrap_or_default();

        let decision = self.rules.decide(&facts);

        // ONLY an allow forwards anything. A step-up is not an admission: the caller has to
        // come back with stronger authentication, and handing the upstream an identity in the
        // meantime would defeat the requirement being made.
        let upstream_headers = match (&decision.action, identity) {
            (Action::Allow, Some(identity)) => upstream_headers_for(identity),
            (Action::Allow, None) | (Action::Deny | Action::StepUp { .. }, _) => Vec::new(),
        };

        ForwardAuthOutcome {
            decision,
            upstream_headers,
            must_delete,
            identity_rejected: None,
        }
    }
}

/// Remove every reserved header the client sent, returning the sanitised facts and the names
/// the adapter must delete.
///
/// Returns the names as the CLIENT spelled them, because that is what an operator needs in
/// order to recognise the proxy or the caller responsible.
#[must_use]
pub fn strip_trusted_headers(mut facts: RequestFacts) -> (RequestFacts, Vec<String>) {
    let mut reserved: Vec<String> = facts
        .headers
        .keys()
        .filter(|name| is_trusted_header(name))
        .cloned()
        .collect();
    // Sorted so the report is stable: `HashMap` iteration order is not, and a log line that
    // reorders itself between identical requests is one nobody can diff.
    reserved.sort_unstable();
    for name in &reserved {
        facts.headers.remove(name);
    }
    (facts, reserved)
}

/// The headers an upstream application should receive for `identity`.
///
/// Private on purpose. It was public, and it takes no decision, so it sat beside the allow
/// gate offering the same output without it. The only way to obtain these headers is through
/// [`ForwardAuth::evaluate`], which applies the gate.
///
/// Absent optional fields are OMITTED rather than sent empty, so an upstream can tell "no
/// email on this account" from "an empty email", which are different facts. Note the
/// interaction recorded on [`ForwardAuthOutcome::must_delete`]: omitting is only safe on a
/// dialect that deletes before setting.
fn upstream_headers_for(identity: &Identity) -> Vec<(String, String)> {
    TRUSTED
        .iter()
        .filter_map(|(name, read)| read(identity).map(|value| ((*name).to_owned(), value)))
        .collect()
}

/// Build request facts from a proxy's forwarded description of the original request.
///
/// Sanitises on the way in, so a dialect adapter cannot forget to.
///
/// Repeated header names are COMBINED with `, ` rather than last-wins. HTTP permits
/// repetition and the criterion names header smuggling through untrusted hops as an attack
/// class; a lossy collect let an adapter's ordering decide which value a rule saw, so a rule
/// denying on `X-Internal: yes` was evadable by sending the header twice. Combining is the
/// RFC 9110 reading and it fails toward NOT matching an exact-value rule, which is the
/// refusing direction.
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
    let mut combined: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for (name, value) in headers {
        combined
            .entry(name)
            .and_modify(|existing| {
                existing.push_str(", ");
                existing.push_str(&value);
            })
            .or_insert(value);
    }
    strip_trusted_headers(RequestFacts {
        method: method.to_owned(),
        host: host.to_owned(),
        path: path.to_owned(),
        headers: combined,
        ..RequestFacts::default()
    })
}

#[cfg(test)]
mod tests {
    use crate::rules::{Criterion, Rule, SubjectCheck};

    use super::*;

    fn identity() -> Identity {
        Identity {
            user: "alice".to_owned(),
            groups: vec!["engineering".to_owned(), "oncall".to_owned()],
            roles: Vec::new(),
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

    /// A rule set that admits ONLY when a reserved header carries a chosen value, with a
    /// trailing deny. This is the fixture that can see stripping: if a client-supplied
    /// reserved header reaches the engine, the first rule matches and the answer flips.
    fn gated_on(name: &str) -> ForwardAuth {
        ForwardAuth::new(RuleSet::new(vec![
            rule(
                "reserved-header-gate",
                vec![Criterion::Header {
                    name: name.to_owned(),
                    value: "admins".to_owned(),
                }],
                Action::Allow,
            ),
            rule("default-deny", vec![], Action::Deny),
        ]))
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

    /// A CLIENT-SUPPLIED RESERVED HEADER CANNOT DECIDE A REQUEST, in any spelling.
    ///
    /// This replaces a test that asserted the forged value was absent from
    /// `upstream_headers` while passing `identity: None`, which makes that vector
    /// unconditionally empty: the assertion could not fail for any implementation. A mutant
    /// that removed stripping entirely passed it.
    ///
    /// The fixture here admits only on the reserved header, so a surviving client value
    /// flips the decision. That is what makes it able to fail.
    #[test]
    fn a_client_supplied_reserved_header_never_decides_a_request() {
        for spelling in [
            "Remote-Groups",
            "remote-groups",
            "REMOTE-GROUPS",
            "ReMoTe-GrOuPs",
            // Same variable to any CGI, FastCGI, WSGI or PHP upstream.
            "Remote_Groups",
            "REMOTE_GROUPS",
            // A parser that trims before lookup sees the reserved name.
            " Remote-Groups",
            "Remote-Groups ",
        ] {
            let outcome =
                gated_on("Remote-Groups").evaluate(request_with(spelling, "admins"), None);
            assert_eq!(
                outcome.decision.action,
                Action::Deny,
                "{spelling}: a client-chosen value must not satisfy a rule on a reserved name"
            );
            assert_eq!(
                outcome.decision.matched.as_deref(),
                Some("default-deny"),
                "{spelling}: and it must fall through to the deny"
            );
            assert_eq!(
                outcome.must_delete,
                vec![spelling.to_owned()],
                "{spelling}: and the adapter is told to delete it"
            );
        }
    }

    /// EVERY EMITTED HEADER NAME IS RESERVED.
    ///
    /// Derived from the EMITTER rather than from the reserved list. The previous version
    /// iterated `TRUSTED_HEADERS` and asserted against `TRUSTED_HEADERS`, so a missing entry,
    /// a duplicate, or a typo corrupted the expectation along with the code. A review
    /// duplicated an entry so `Remote-Name` was forgeable, and this test passed.
    #[test]
    fn every_header_the_emitter_can_send_is_reserved_against_the_client() {
        let full = Identity {
            user: "u".to_owned(),
            groups: vec!["g".to_owned()],
            roles: vec!["r".to_owned()],
            email: Some("e@example.test".to_owned()),
            name: Some("n".to_owned()),
        };
        let emitted = upstream_headers_for(&full);
        assert_eq!(
            emitted.len(),
            4,
            "all four fields are populated in this fixture"
        );

        for (name, _) in &emitted {
            assert!(
                is_trusted_header(name),
                "{name} is emitted upstream but a client could send it"
            );
        }

        // And the names are distinct: a duplicated entry would silently drop one field.
        let mut names: Vec<&str> = emitted.iter().map(|(name, _)| name.as_str()).collect();
        names.sort_unstable();
        let distinct = names.len();
        names.dedup();
        assert_eq!(names.len(), distinct, "two entries share a header name");
    }

    /// AN INVALID IDENTITY IS A REFUSAL, not a silently dropped header.
    ///
    /// A carriage return in a subject is request splitting: the upstream reads the injected
    /// line as an authoritative header. Dropping it while the admission stands would serve
    /// the request as some other principal, or as none.
    #[test]
    fn an_identity_that_cannot_be_serialised_is_refused() {
        let cases = [
            (
                "crlf in the subject",
                Identity {
                    user: "alice\r\nRemote-Groups: admins".to_owned(),
                    ..identity()
                },
                IdentityError::ControlCharacter { field: "user" },
            ),
            (
                "newline in the display name",
                Identity {
                    name: Some("A\nB".to_owned()),
                    ..identity()
                },
                IdentityError::ControlCharacter { field: "name" },
            ),
            (
                "crlf in the email",
                Identity {
                    email: Some("a@b\r\nX-Admin: 1".to_owned()),
                    ..identity()
                },
                IdentityError::ControlCharacter { field: "email" },
            ),
            (
                "a comma inside one group name",
                Identity {
                    groups: vec!["Finance, EU".to_owned()],
                    ..identity()
                },
                IdentityError::SeparatorInGroup {
                    group: "Finance, EU".to_owned(),
                },
            ),
            (
                "an empty subject",
                Identity {
                    user: String::new(),
                    ..identity()
                },
                IdentityError::EmptySubject,
            ),
        ];

        for (what, bad, expected) in cases {
            let outcome = open().evaluate(request_with("X-Other", "kept"), Some(&bad));
            assert_eq!(
                outcome.identity_rejected.as_ref(),
                Some(&expected),
                "{what}: must be rejected by name"
            );
            assert_eq!(
                outcome.decision.action,
                Action::Deny,
                "{what}: and the request refused, not admitted with a missing header"
            );
            assert!(outcome.upstream_headers.is_empty(), "{what}");
        }
    }

    /// ONE GROUP NAMED `a,b` IS NOT TWO GROUPS.
    ///
    /// On the wire the join makes them byte-identical, so an upstream splitting on commas
    /// reads a single directory-synced group named `Finance, EU` as membership in two.
    #[test]
    fn a_comma_in_a_group_name_cannot_forge_a_second_membership() {
        let one = Identity {
            groups: vec!["users,admins".to_owned()],
            ..identity()
        };
        let two = Identity {
            groups: vec!["users".to_owned(), "admins".to_owned()],
            ..identity()
        };
        assert_eq!(
            one.validate(),
            Err(IdentityError::SeparatorInGroup {
                group: "users,admins".to_owned()
            })
        );
        assert_eq!(
            two.validate(),
            Ok(()),
            "the genuine two-group case still works"
        );
    }

    /// THE ENGINE DECIDES ABOUT THE PRINCIPAL THAT IS FORWARDED.
    ///
    /// They were independent inputs. A review authorised `alice` on her group membership and
    /// told the upstream it was serving `mallory`, a member of `admins`.
    #[test]
    fn the_decided_principal_is_the_forwarded_principal() {
        let gated = ForwardAuth::new(RuleSet::new(vec![
            rule(
                "engineering-only",
                vec![Criterion::Subject(SubjectCheck::InGroup(
                    "engineering".to_owned(),
                ))],
                Action::Allow,
            ),
            rule("default-deny", vec![], Action::Deny),
        ]));

        // Facts claim alice/engineering; the authenticator says mallory/admins.
        let mut facts = request_with("X-Other", "kept");
        facts.subject = Some("alice".to_owned());
        facts.groups = vec!["engineering".to_owned()];
        let mallory = Identity {
            user: "mallory".to_owned(),
            groups: vec!["admins".to_owned(), "finance".to_owned()],
            roles: Vec::new(),
            email: None,
            name: None,
        };

        let outcome = gated.evaluate(facts, Some(&mallory));
        assert_eq!(
            outcome.decision.action,
            Action::Deny,
            "the decision must be about mallory, who is not in engineering"
        );
        assert!(outcome.upstream_headers.is_empty());

        // And the converse: the real member is admitted and forwarded as herself.
        let engineer = Identity {
            user: "alice".to_owned(),
            groups: vec!["engineering".to_owned()],
            roles: Vec::new(),
            email: None,
            name: None,
        };
        let outcome = gated.evaluate(request_with("X-Other", "kept"), Some(&engineer));
        assert_eq!(outcome.decision.action, Action::Allow);
        assert_eq!(
            outcome.upstream_headers[0],
            ("Remote-User".to_owned(), "alice".to_owned())
        );
    }

    /// A DENIAL FORWARDS NOTHING, even with a fully authenticated identity in hand.
    #[test]
    fn a_denied_request_forwards_no_identity() {
        let shut = ForwardAuth::new(RuleSet::new(vec![rule("shut", vec![], Action::Deny)]));
        let outcome = shut.evaluate(request_with("X-Other", "kept"), Some(&identity()));
        assert_eq!(outcome.decision.action, Action::Deny);
        assert!(
            outcome.upstream_headers.is_empty(),
            "a refusal must not hand the upstream an identity for a request it was told to refuse"
        );
    }

    /// A STEP-UP FORWARDS NOTHING EITHER. It is not an admission.
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
            ]
        );
        assert_eq!(
            outcome.must_delete,
            vec!["Remote-User".to_owned()],
            "and the forged one is flagged for deletion by the adapter"
        );
    }

    /// AN ANONYMOUS ADMISSION FORWARDS NOTHING.
    #[test]
    fn an_anonymous_admission_forwards_no_identity() {
        let outcome = open().evaluate(request_with("X-Other", "kept"), None);
        assert_eq!(outcome.decision.action, Action::Allow);
        assert!(outcome.upstream_headers.is_empty());
    }

    /// AN ABSENT OPTIONAL FIELD IS OMITTED, not sent empty.
    #[test]
    fn absent_optional_fields_are_omitted_rather_than_blank() {
        let sparse = Identity {
            user: "bob".to_owned(),
            groups: Vec::new(),
            roles: Vec::new(),
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
    #[test]
    fn an_ordinary_header_is_not_stripped() {
        let outcome = gated_on("X-Service").evaluate(request_with("X-Service", "admins"), None);
        assert_eq!(
            outcome.decision.matched.as_deref(),
            Some("reserved-header-gate"),
            "an ordinary header must still reach a rule written about it"
        );
        assert!(outcome.must_delete.is_empty());
    }

    /// THE DELETION INSTRUCTION IS STABLE, so a log line does not reorder between requests.
    #[test]
    fn the_deletion_instruction_is_sorted() {
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

    /// THE PROXY ADAPTER SANITISES, and does not lose a repeated header.
    ///
    /// HTTP permits repetition, and the criterion names header smuggling through untrusted
    /// hops as an attack class. A last-wins collect let an adapter's ordering decide which
    /// value a rule saw, so a rule denying on a header was evadable by sending it twice.
    #[test]
    fn the_proxy_adapter_sanitises_and_combines_repeated_headers() {
        let (facts, must_delete) = facts_from_proxy(
            "GET",
            "app.example.test",
            "/",
            vec![
                ("remote-user".to_owned(), "root".to_owned()),
                ("x-service".to_owned(), "billing".to_owned()),
                ("x-service".to_owned(), "admin".to_owned()),
            ],
        );
        assert_eq!(must_delete, vec!["remote-user".to_owned()]);
        assert!(!facts.headers.contains_key("remote-user"));
        assert_eq!(
            facts.headers.get("x-service").map(String::as_str),
            Some("billing, admin"),
            "neither value may be dropped: an exact-value rule then matches neither, \
             which is the refusing direction"
        );
    }
}
