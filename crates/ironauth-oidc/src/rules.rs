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
        self.walk(facts, &mut Silent)
    }

    /// The decision, plus a trace of how every rule answered.
    ///
    /// This is what answers "why was this denied" for a request an operator is staring at:
    /// each rule by name, and for a rule that did not match, the INDEX and rendering of the
    /// criterion that stopped it.
    ///
    /// Shares [`RuleSet::walk`] with [`RuleSet::decide`] rather than re-deriving the answer.
    /// Two implementations of one decision is how a trace ends up explaining something the
    /// engine did not do, and a trace that disagrees with enforcement is worse than none:
    /// it is believed. `the_trace_agrees_with_the_decision_on_every_corpus_row` pins it.
    #[must_use]
    pub fn explain(&self, facts: &RequestFacts) -> Explanation {
        let mut recording = Recording::default();
        let decision = self.walk(facts, &mut recording);
        Explanation {
            decision,
            trace: Trace {
                rules: recording.rules,
            },
        }
    }

    /// What the engine WOULD decide, in a form that cannot be enforced.
    ///
    /// See [`DryRun`] for why this returns its own type rather than a [`Decision`].
    #[must_use]
    pub fn dry_run(&self, facts: &RequestFacts) -> DryRun {
        DryRun {
            explanation: self.explain(facts),
        }
    }

    /// The single implementation. `decide`, `explain` and `dry_run` all come through here.
    fn walk<R: Recorder>(&self, facts: &RequestFacts, recorder: &mut R) -> Decision {
        let mut decided: Option<Decision> = None;
        for rule in &self.rules {
            if decided.is_some() {
                // Only a recording walk continues past the decision, and only to mark the
                // rules that were never consulted. A plain `decide` returns below, so it
                // does exactly the work it did before tracing existed.
                recorder.not_reached(rule);
                continue;
            }
            // Captures are per-rule: a fresh map each time, so one rule can never read what
            // another rule's pattern bound.
            let mut captures: HashMap<String, String> = HashMap::new();
            let mut failed_at: Option<usize> = None;
            for (index, criterion) in rule.criteria.iter().enumerate() {
                if !matches(criterion, facts, &mut captures) {
                    failed_at = Some(index);
                    // Stop at the FIRST failure, preserving the short-circuit that
                    // `all()` gave us. It is also the right answer for a trace: the
                    // criteria after it never ran, so claiming anything about them
                    // would be a guess.
                    break;
                }
            }
            if let Some(index) = failed_at {
                recorder.failed(rule, index);
                continue;
            }
            recorder.matched(rule);
            let decision = Decision {
                action: rule.action.clone(),
                matched: Some(rule.name.clone()),
            };
            if !R::RECORDS {
                // A non-recording walk has its answer and nothing left to record, so it
                // stops here, doing exactly the work it did before tracing existed.
                return decision;
            }
            decided = Some(decision);
        }
        decided.unwrap_or_else(Decision::no_match)
    }
}

/// Where a walk reports what each rule did.
///
/// A trait with a no-op implementation, so tracing costs a non-tracing caller nothing: the
/// `RECORDS` constant lets `walk` return at the matching rule exactly as it used to, and the
/// criterion rendering is only built by the implementation that keeps it.
trait Recorder {
    /// Whether this recorder keeps anything. `false` lets `walk` stop at the first match.
    const RECORDS: bool;
    fn matched(&mut self, rule: &Rule);
    fn failed(&mut self, rule: &Rule, criterion_index: usize);
    fn not_reached(&mut self, rule: &Rule);
}

/// The recorder for [`RuleSet::decide`]: keeps nothing, allocates nothing.
struct Silent;

impl Recorder for Silent {
    const RECORDS: bool = false;
    fn matched(&mut self, _rule: &Rule) {}
    fn failed(&mut self, _rule: &Rule, _criterion_index: usize) {}
    fn not_reached(&mut self, _rule: &Rule) {}
}

/// The recorder for [`RuleSet::explain`].
#[derive(Default)]
struct Recording {
    rules: Vec<RuleTrace>,
}

impl Recorder for Recording {
    const RECORDS: bool = true;

    fn matched(&mut self, rule: &Rule) {
        self.rules.push(RuleTrace {
            rule: rule.name.clone(),
            outcome: RuleOutcome::Matched,
        });
    }

    fn failed(&mut self, rule: &Rule, criterion_index: usize) {
        self.rules.push(RuleTrace {
            rule: rule.name.clone(),
            outcome: RuleOutcome::Failed {
                criterion_index,
                criterion: describe(&rule.criteria[criterion_index]),
            },
        });
    }

    fn not_reached(&mut self, rule: &Rule) {
        self.rules.push(RuleTrace {
            rule: rule.name.clone(),
            outcome: RuleOutcome::NotReached,
        });
    }
}

/// How one rule answered during a traced walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleOutcome {
    /// Every criterion held, so this rule decided.
    Matched,
    /// A criterion did not hold, and evaluation of this rule stopped there.
    Failed {
        /// The zero-based position of the criterion that stopped it.
        criterion_index: usize,
        /// That criterion, rendered for a human.
        criterion: String,
    },
    /// Never evaluated, because an earlier rule already decided.
    ///
    /// Distinct from `Failed` on purpose. "This rule would have allowed you, but a rule
    /// above it denied first" is the single most common thing an operator needs to see, and
    /// collapsing it into "did not match" hides it.
    NotReached,
}

/// One rule's line in a trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleTrace {
    /// The rule's name.
    pub rule: String,
    /// What it did.
    pub outcome: RuleOutcome,
}

/// Every rule's answer, in evaluation order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trace {
    /// One entry per rule, in the order the rule set declares them, which is the order
    /// they were evaluated in.
    pub rules: Vec<RuleTrace>,
}

/// The decision and the trace that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Explanation {
    /// What the engine decided.
    pub decision: Decision,
    /// How every rule answered.
    pub trace: Trace,
}

impl Explanation {
    /// A one-line answer to "why was this denied", or `None` when nothing was denied.
    ///
    /// # Why this lives here and not on [`Trace`]
    ///
    /// It was on `Trace` first, and that was wrong in a way a test caught immediately: a
    /// trace records what each rule DID, not what the verdict was, so a matched rule looked
    /// like a denial even when its action was `Allow`. Reporting "denied by rule open" for
    /// an admission is precisely the trace-contradicts-the-decision failure this whole
    /// design is trying to avoid. The explanation holds both halves, so it is the only place
    /// that can answer honestly.
    ///
    /// Three shapes, because an operator acts differently on each: a rule denied by name, no
    /// rule matched so the default refusal applied, or no rules exist at all.
    ///
    /// # A DENIAL, not "anything that is not an allow"
    ///
    /// This guarded `Action::Allow` first and let everything else fall through to "denied by
    /// rule X". [`Action::StepUp`] is a third variant, and its own documentation says it is
    /// distinct from `Deny` precisely because the caller can act on it, so reporting a
    /// challenge as a denial tells an operator their rules refuse users the rules would in
    /// fact merely challenge.
    ///
    /// That is the same explanation-contradicts-the-decision bug this type was created to
    /// fix, surviving one variant over: the first fix special-cased `Allow` and stopped
    /// there. Matching on `Deny` positively, rather than on the absence of `Allow`, is what
    /// makes a fourth action a compile error here instead of a wrong sentence. Use
    /// [`Explanation::reason`] when you want a line for every outcome.
    #[must_use]
    pub fn why_denied(&self) -> Option<String> {
        if !matches!(self.decision.action, Action::Deny) {
            return None;
        }
        if let Some(rule) = self.decision.matched.as_deref() {
            return Some(format!("denied by rule {rule}"));
        }
        if self.trace.rules.is_empty() {
            return Some("denied because no rules are configured".to_owned());
        }
        let attempts: Vec<String> = self
            .trace
            .rules
            .iter()
            .filter_map(|entry| match &entry.outcome {
                RuleOutcome::Failed {
                    criterion_index,
                    criterion,
                } => Some(format!(
                    "{} failed at criterion {criterion_index} ({criterion})",
                    entry.rule
                )),
                _ => None,
            })
            .collect();
        Some(format!(
            "denied because no rule matched: {}",
            attempts.join("; ")
        ))
    }

    /// One line describing the outcome, whatever it was.
    ///
    /// [`Explanation::why_denied`] answers criterion 5's question and is therefore `None`
    /// for anything that is not a denial. An operator rehearsing a rollout still wants a
    /// sentence for an admission or a challenge, and leaving them without one is how a
    /// caller ends up reaching for `why_denied` and printing "no reason" next to a
    /// step-up.
    ///
    /// Matches on the action exhaustively, so a new [`Action`] cannot be added without
    /// deciding what this says about it.
    #[must_use]
    pub fn reason(&self) -> String {
        match (&self.decision.action, self.decision.matched.as_deref()) {
            (Action::Deny, _) => self.why_denied().unwrap_or_else(|| "denied".to_owned()),
            (Action::Allow, Some(rule)) => format!("allowed by rule {rule}"),
            (Action::Allow, None) => "allowed".to_owned(),
            (Action::StepUp { acr }, Some(rule)) => {
                format!("rule {rule} requires step-up to {acr}")
            }
            (Action::StepUp { acr }, None) => format!("step-up to {acr} required"),
        }
    }
}

/// What the engine WOULD decide, in a form that cannot be enforced.
///
/// # Why this is its own type
///
/// "Dry-run never enforces" is a property, and a mode flag cannot carry it: a boolean on the
/// rule set is one forgotten branch away from a dry-run verdict reaching the enforcement
/// path, and that failure is silent and admits or denies real traffic.
///
/// So dry-run yields no [`Decision`] at all. Every accessor here is named `would_` and
/// returns a borrow or a copy, never an owned `Decision`, so a dry-run answer cannot be
/// handed to a caller that expects a real one. The type system does the enforcing, which is
/// the only way this property survives someone refactoring in a hurry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DryRun {
    explanation: Explanation,
}

impl DryRun {
    /// Whether the engine would have allowed the request.
    #[must_use]
    pub fn would_allow(&self) -> bool {
        matches!(self.explanation.decision.action, Action::Allow)
    }

    /// The action the engine would have taken.
    #[must_use]
    pub fn would_act(&self) -> &Action {
        &self.explanation.decision.action
    }

    /// The rule that would have decided, if any.
    #[must_use]
    pub fn would_match(&self) -> Option<&str> {
        self.explanation.decision.matched.as_deref()
    }

    /// The full trace, for logging what a rollout would have done.
    #[must_use]
    pub fn trace(&self) -> &Trace {
        &self.explanation.trace
    }

    /// Why the rehearsal would have denied, or `None` if it would have allowed.
    ///
    /// The whole point of a dry run is the line an operator reads before turning
    /// enforcement on, so a rehearsal that could not answer "why" would only be half of
    /// criterion 5.
    #[must_use]
    pub fn would_deny_because(&self) -> Option<String> {
        self.explanation.why_denied()
    }

    /// One line describing what the rehearsal would do, whatever that is.
    ///
    /// See [`Explanation::reason`]. This is the line to log for a dry-run rollout, because
    /// [`DryRun::would_deny_because`] is deliberately empty for an admission or a challenge.
    #[must_use]
    pub fn would_because(&self) -> String {
        self.explanation.reason()
    }
}

/// Render one criterion for a trace line.
///
/// Deliberately does NOT print header values or subject identifiers beyond what the rule
/// itself already contains: a trace is written to a log, and a rule's own configuration is
/// the operator's, while the request's values are the caller's.
fn describe(criterion: &Criterion) -> String {
    match criterion {
        Criterion::Method(allowed) => format!("method in {allowed:?}"),
        Criterion::Host(host) => format!("host == {host}"),
        Criterion::PathPrefix(prefix) => format!("path under {prefix}"),
        Criterion::PathMatches(pattern) => format!("path matches /{}/", pattern.as_str()),
        Criterion::Header { name, .. } => format!("header {name} has the configured value"),
        Criterion::Subject(check) => match check {
            SubjectCheck::Is(subject) => format!("subject is {subject}"),
            SubjectCheck::InGroup(group) => format!("subject in group {group}"),
            SubjectCheck::HasRole(role) => format!("subject has role {role}"),
            SubjectCheck::EqualsCapture(name) => format!("subject equals capture {name}"),
            SubjectCheck::Authenticated => "subject is authenticated".to_owned(),
            SubjectCheck::Anonymous => "subject is anonymous".to_owned(),
        },
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
            // A THIRD ACTION. Without a StepUp row, every test that branches on the action
            // ran over two of three variants, which is how `why_denied` shipped calling a
            // challenge a denial and `would_allow` went unpinned for it.
            rule(
                "payments-need-mfa",
                vec![Criterion::PathPrefix("/payments".to_owned())],
                Action::StepUp {
                    acr: "mfa".to_owned(),
                },
            ),
            // DELIBERATELY OVERLAPS the rule above: both match /payments. Until this row
            // existed no corpus request matched more than ONE rule, so every assertion
            // comparing "the rules marked Matched" against "the rule the decision names"
            // compared at most one element, and could not tell first-match from last-match.
            allow(
                "payments-catch-all",
                vec![Criterion::PathPrefix("/payments".to_owned())],
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
            Case {
                name: "a step-up is a third answer, and the FIRST of two matching rules wins",
                facts: RequestFacts {
                    path: "/payments/new".to_owned(),
                    ..facts()
                },
                expect: Some("payments-need-mfa"),
                action: Action::StepUp {
                    acr: "mfa".to_owned(),
                },
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

    // -----------------------------------------------------------------------
    // Criterion 5: decision traces and dry-run answer "why was this denied",
    // asserted on trace CONTENT, and dry-run never enforces.
    // -----------------------------------------------------------------------

    /// THE TRACE AND THE DECISION CANNOT DISAGREE, across the whole corpus.
    ///
    /// `explain` and `decide` share one walk precisely so this holds. It is asserted anyway,
    /// because the sharing is a code arrangement that a later refactor can undo, and a trace
    /// that disagrees with enforcement is worse than no trace: it gets believed. This is the
    /// guard that notices the day someone gives `explain` its own loop.
    #[test]
    fn the_trace_agrees_with_the_decision_on_every_corpus_row() {
        let set = corpus_rules();
        for case in corpus_cases() {
            let decided = set.decide(&case.facts);
            let explained = set.explain(&case.facts);
            assert_eq!(
                explained.decision, decided,
                "{}: explain and decide must reach the same answer",
                case.name
            );

            // And the trace's own account must agree with that answer: the rule it marks
            // Matched is the rule the decision names.
            let matched: Vec<&str> = explained
                .trace
                .rules
                .iter()
                .filter(|entry| entry.outcome == RuleOutcome::Matched)
                .map(|entry| entry.rule.as_str())
                .collect();
            let expected: Vec<&str> = decided.matched.as_deref().into_iter().collect();
            assert_eq!(
                matched, expected,
                "{}: exactly the deciding rule is marked Matched",
                case.name
            );
        }
    }

    /// A DENIAL NAMES THE CRITERION THAT STOPPED EACH RULE, by index and by rendering.
    ///
    /// This is criterion 5's "why was this denied", asserted on content rather than on the
    /// trace merely being non-empty.
    #[test]
    fn a_denied_request_reports_which_criterion_stopped_each_rule() {
        let set = RuleSet::new(vec![
            allow(
                "admins-only",
                vec![
                    Criterion::PathPrefix("/admin".to_owned()),
                    Criterion::Subject(SubjectCheck::HasRole("admin".to_owned())),
                ],
            ),
            allow(
                "internal-network",
                vec![Criterion::Host("internal.example.com".to_owned())],
            ),
        ]);

        // On /admin as a signed-in NON-admin: rule one clears its path check and fails the
        // role check at index 1; rule two fails its host check at index 0.
        let request = RequestFacts {
            path: "/admin/keys".to_owned(),
            subject: Some("usr_1".to_owned()),
            ..facts()
        };
        let explained = set.explain(&request);
        assert_eq!(explained.decision.action, Action::Deny);
        assert_eq!(explained.decision.matched, None);

        assert_eq!(
            explained.trace.rules,
            vec![
                RuleTrace {
                    rule: "admins-only".to_owned(),
                    outcome: RuleOutcome::Failed {
                        criterion_index: 1,
                        criterion: "subject has role admin".to_owned(),
                    },
                },
                RuleTrace {
                    rule: "internal-network".to_owned(),
                    outcome: RuleOutcome::Failed {
                        criterion_index: 0,
                        criterion: "host == internal.example.com".to_owned(),
                    },
                },
            ],
            "the trace must name the criterion that stopped each rule, not merely that it failed"
        );

        let why = explained.why_denied().expect("a denial has a reason");
        assert!(why.contains("no rule matched"), "{why}");
        assert!(why.contains("admins-only failed at criterion 1"), "{why}");
        assert!(why.contains("subject has role admin"), "{why}");
    }

    /// THE INDEX IS THE FIRST FAILURE, and the criteria after it are not claimed about.
    ///
    /// `all()` short-circuits, so a criterion after a failing one never runs. A trace that
    /// reported on it would be asserting something the engine did not evaluate.
    #[test]
    fn the_trace_stops_at_the_first_failing_criterion() {
        let set = RuleSet::new(vec![allow(
            "three-checks",
            vec![
                Criterion::Method(vec!["GET".to_owned()]),
                // Fails here, at index 1.
                Criterion::Host("nowhere.example.com".to_owned()),
                // Would also fail, but must never be evaluated or reported.
                Criterion::PathPrefix("/unreachable".to_owned()),
            ],
        )]);

        let explained = set.explain(&facts());
        assert_eq!(
            explained.trace.rules,
            vec![RuleTrace {
                rule: "three-checks".to_owned(),
                outcome: RuleOutcome::Failed {
                    criterion_index: 1,
                    criterion: "host == nowhere.example.com".to_owned(),
                },
            }],
            "the first failure is the whole story; index 2 never ran"
        );
    }

    /// A RULE BELOW THE DECIDING ONE IS `NotReached`, NOT `Failed`.
    ///
    /// "A rule further down would have allowed you, but this one denied first" is the most
    /// common thing an operator needs from a trace, and reporting it as a failure to match
    /// hides it completely.
    #[test]
    fn rules_below_the_decision_are_marked_unreached_rather_than_failed() {
        let set = RuleSet::new(vec![
            deny(
                "blanket-deny",
                vec![Criterion::PathPrefix("/admin".to_owned())],
            ),
            allow(
                "would-have-allowed",
                vec![
                    Criterion::PathPrefix("/admin".to_owned()),
                    Criterion::Subject(SubjectCheck::HasRole("admin".to_owned())),
                ],
            ),
        ]);

        let request = RequestFacts {
            path: "/admin/keys".to_owned(),
            subject: Some("usr_root".to_owned()),
            roles: vec!["admin".to_owned()],
            ..facts()
        };
        let explained = set.explain(&request);
        assert_eq!(explained.decision.matched.as_deref(), Some("blanket-deny"));
        assert_eq!(
            explained.trace.rules,
            vec![
                RuleTrace {
                    rule: "blanket-deny".to_owned(),
                    outcome: RuleOutcome::Matched,
                },
                RuleTrace {
                    rule: "would-have-allowed".to_owned(),
                    outcome: RuleOutcome::NotReached,
                },
            ]
        );

        let why = explained.why_denied().expect("denied by a rule");
        assert_eq!(why, "denied by rule blanket-deny");
    }

    /// AN ALLOWED REQUEST HAS NO DENIAL REASON.
    ///
    /// `why_denied` returning something for an admission would be a trace that contradicts
    /// the decision it accompanies.
    #[test]
    fn an_allowed_request_has_nothing_to_explain() {
        let set = RuleSet::new(vec![allow(
            "open",
            vec![Criterion::PathPrefix("/public".to_owned())],
        )]);
        let request = RequestFacts {
            path: "/public/logo.png".to_owned(),
            ..facts()
        };
        let explained = set.explain(&request);
        assert_eq!(explained.decision.action, Action::Allow);
        assert_eq!(
            explained.why_denied(),
            None,
            "an admission has no denial to explain"
        );
    }

    /// AN EMPTY RULE SET SAYS SO, rather than blaming a rule.
    #[test]
    fn an_empty_rule_set_explains_itself() {
        let explained = RuleSet::default().explain(&facts());
        assert_eq!(
            explained.decision,
            Decision {
                action: Action::Deny,
                matched: None
            }
        );
        assert_eq!(
            explained.why_denied().as_deref(),
            Some("denied because no rules are configured"),
            "the default refusal is a different situation from a rule refusing"
        );
    }

    /// DRY-RUN REPORTS WHAT WOULD HAPPEN AND AGREES WITH ENFORCEMENT.
    #[test]
    fn dry_run_reports_the_same_answer_enforcement_would_reach() {
        let set = corpus_rules();
        for case in corpus_cases() {
            let enforced = set.decide(&case.facts);
            let dry = set.dry_run(&case.facts);
            assert_eq!(
                dry.would_act(),
                &enforced.action,
                "{}: dry-run must predict enforcement, or it is not a rehearsal",
                case.name
            );
            assert_eq!(
                dry.would_match(),
                enforced.matched.as_deref(),
                "{}",
                case.name
            );
            assert_eq!(
                dry.would_allow(),
                matches!(enforced.action, Action::Allow),
                "{}",
                case.name
            );
        }
    }

    /// DRY-RUN NEVER ENFORCES, and this is a property of the TYPE rather than of care.
    ///
    /// A boolean mode is one forgotten branch from a rehearsal verdict reaching the
    /// enforcement path. [`DryRun`] therefore yields no [`Decision`] at all: every accessor
    /// is a borrow or a copy named `would_`. This test drives a request that dry-run says
    /// would be DENIED and shows the enforcement seam is untouched by it.
    #[test]
    fn a_dry_run_denial_cannot_reach_the_enforcement_seam() {
        // The seam: everything that enforces takes a Decision. DryRun cannot produce one.
        fn enforce(decision: &Decision) -> bool {
            matches!(decision.action, Action::Allow)
        }

        let set = RuleSet::new(vec![deny(
            "no-admin",
            vec![Criterion::PathPrefix("/admin".to_owned())],
        )]);
        let request = RequestFacts {
            path: "/admin/keys".to_owned(),
            ..facts()
        };

        let dry = set.dry_run(&request);
        assert!(
            !dry.would_allow(),
            "the rehearsal says this would be denied"
        );
        assert_eq!(dry.would_match(), Some("no-admin"));

        // The only way to reach `enforce` is to ask the engine for a real decision. There is
        // no From<DryRun> for Decision, no into_decision, and no owned Decision behind any
        // accessor -- so a caller cannot pass a rehearsal where enforcement is expected even
        // by mistake. What follows is deliberate, and it is the ONLY route.
        let real = set.decide(&request);
        assert!(!enforce(&real));

        // And the rehearsal carries the full trace, which is the point of running one.
        assert_eq!(
            dry.trace().rules,
            vec![RuleTrace {
                rule: "no-admin".to_owned(),
                outcome: RuleOutcome::Matched,
            }]
        );
    }

    /// A TRACE LINE DOES NOT CARRY THE REQUEST'S OWN VALUES.
    ///
    /// Traces go to logs. A rule's configuration belongs to the operator who wrote it; the
    /// header values and subject identifiers on the request belong to the caller, and a
    /// trace is not the place to copy them.
    #[test]
    fn a_trace_renders_the_rule_not_the_request() {
        let set = RuleSet::new(vec![allow(
            "service-only",
            vec![Criterion::Header {
                name: "X-Service".to_owned(),
                value: "super-secret-token".to_owned(),
            }],
        )]);
        let mut request = facts();
        request
            .headers
            .insert("x-service".to_owned(), "the-callers-value".to_owned());

        let explained = set.explain(&request);
        let rendered = format!("{:?}", explained.trace);
        assert!(
            rendered.contains("X-Service"),
            "the rule's own header NAME is the operator's and is useful: {rendered}"
        );
        assert!(
            !rendered.contains("the-callers-value"),
            "the caller's header VALUE must not land in a log line: {rendered}"
        );
        assert!(
            !rendered.contains("super-secret-token"),
            "nor the configured value it is compared against: {rendered}"
        );
    }

    /// A REHEARSAL ANSWERS "WHY" TOO, in the same words enforcement would.
    #[test]
    fn a_dry_run_explains_its_denial_the_same_way_enforcement_does() {
        let set = RuleSet::new(vec![allow(
            "admins-only",
            vec![
                Criterion::PathPrefix("/admin".to_owned()),
                Criterion::Subject(SubjectCheck::HasRole("admin".to_owned())),
            ],
        )]);
        let request = RequestFacts {
            path: "/admin/keys".to_owned(),
            subject: Some("usr_1".to_owned()),
            ..facts()
        };

        let dry = set.dry_run(&request);
        let explained = set.explain(&request);
        assert_eq!(
            dry.would_deny_because(),
            explained.why_denied(),
            "a rehearsal and the real thing must give the operator the same sentence"
        );
        let why = dry.would_deny_because().expect("would have denied");
        assert!(why.contains("subject has role admin"), "{why}");
    }

    /// THE FENCE ITSELF: no accessor on [`DryRun`] hands back an owned [`Decision`].
    ///
    /// The tests above show a rehearsal does not enforce. They cannot show it CANNOT, because
    /// that is a property of the API surface rather than of any single call, and a test
    /// inside the module cannot prove the absence of a method.
    ///
    /// So this is a SOURCE SCAN, and worth being honest about: it reads the text of the
    /// `impl DryRun` block and fails if anything there returns an owned `Decision`, or if a
    /// conversion into one appears. It catches the regression it is aimed at -- somebody
    /// adding an owned accessor or a conversion in a hurry -- and it does not pretend to
    /// catch a caller who deliberately rebuilds a `Decision` from the borrows on offer,
    /// which is possible and documented on [`DryRun`].
    ///
    /// The needle was once the literal `-> Decision`, and a review walked past it with
    /// `-> Option<Decision>`: precisely the regression the sentence above names, missed
    /// because the check was written against one SPELLING of the property rather than the
    /// property. It now rejects any owned return type mentioning `Decision` or
    /// `Explanation`, the latter because its `decision` field is public.
    #[test]
    fn dry_run_exposes_no_owned_decision() {
        // Scan the PRODUCTION half only, cutting at the test module.
        //
        // This is load bearing, and it took three tries to get right. The scan first matched
        // its own assertion string, then its own doc comment. Both times the file was
        // entirely correct and the guard failed. A source scan whose own text can satisfy it
        // is measuring the wrong thing, and the durable fix is not a cleverer needle but a
        // narrower haystack: the property is about the shipped API, so the tests are not part
        // of it.
        let whole = include_str!("rules.rs");
        let source = whole
            .split_once("\n#[cfg(test)]")
            .map_or(whole, |(production, _)| production);

        let start = source
            .find("\nimpl DryRun {")
            .expect("the DryRun impl block is still named that");
        let block = &source[start..];
        let end = block.find("\n}\n").expect("the impl block terminates");
        let block = &block[..end];

        for (offset, line) in block.lines().enumerate() {
            let line = line.trim();
            let Some((_, returns)) = line.split_once("->") else {
                continue;
            };
            // ANY owned escape, not the literal "-> Decision".
            //
            // The needle was that literal, and a review walked straight past it with
            // `-> Option<Decision>`, which is the very shape the comment here named as the
            // thing to catch. A borrow is fine (a caller can clone what it sees anyway, see
            // the note on `DryRun`); what must not exist is an accessor handing back an
            // owned verdict, in a wrapper or otherwise. `Explanation` counts, because its
            // `decision` field is public.
            let owned = !returns.trim_start().starts_with('&');
            for escape in ["Decision", "Explanation"] {
                assert!(
                    !(owned && returns.contains(escape)),
                    "DryRun line {offset} returns an owned {escape}, which puts a rehearsal \
                     on the enforcement path: {line}"
                );
            }
        }

        assert!(
            !source.contains("impl From<DryRun> for Decision"),
            "a From conversion would let a rehearsal be passed wherever a Decision is expected"
        );
        // The accessors that SHOULD be there, so this test fails if the block is renamed or
        // emptied rather than silently passing over nothing.
        for expected in [
            "pub fn would_allow",
            "pub fn would_act",
            "pub fn would_match",
            "pub fn would_deny_because",
            "pub fn would_because",
        ] {
            assert!(
                block.contains(expected),
                "expected {expected} in the DryRun block; if it moved, this scan is no longer \
                 reading what it thinks it is"
            );
        }
    }

    /// A STEP-UP IS NOT A DENIAL, and `why_denied` must not call it one.
    ///
    /// `why_denied` guarded `Action::Allow` and let everything else fall through to "denied
    /// by rule X", so a challenge was reported as a refusal. That is the same
    /// explanation-contradicts-the-decision bug this type exists to prevent, one variant
    /// over, and it reached `DryRun` too: an operator rehearsing a rollout was told their
    /// rules deny users the rules would merely challenge.
    #[test]
    fn a_step_up_is_not_reported_as_a_denial() {
        let set = RuleSet::new(vec![rule(
            "mfa-for-payments",
            vec![Criterion::PathPrefix("/payments".to_owned())],
            Action::StepUp {
                acr: "mfa".to_owned(),
            },
        )]);
        let request = RequestFacts {
            path: "/payments/new".to_owned(),
            ..facts()
        };

        let explained = set.explain(&request);
        assert_eq!(
            explained.decision.action,
            Action::StepUp {
                acr: "mfa".to_owned()
            }
        );
        assert_eq!(
            explained.why_denied(),
            None,
            "a challenge is not a denial, and saying it is misreports the rule set"
        );
        assert_eq!(
            set.dry_run(&request).would_deny_because(),
            None,
            "and the rehearsal must not report one either"
        );

        // But the operator is not left without a sentence.
        assert_eq!(
            explained.reason(),
            "rule mfa-for-payments requires step-up to mfa"
        );
        assert_eq!(set.dry_run(&request).would_because(), explained.reason());
    }

    /// `would_allow` IS ALLOW, not "anything that is not a denial".
    ///
    /// Reporting a step-up as "would allow" is the admitting direction of the mistake, and
    /// the corpus had no third-action row to catch it.
    #[test]
    fn a_step_up_does_not_count_as_would_allow() {
        let set = RuleSet::new(vec![rule(
            "mfa",
            vec![],
            Action::StepUp {
                acr: "mfa".to_owned(),
            },
        )]);
        let dry = set.dry_run(&facts());
        assert!(
            !dry.would_allow(),
            "a step-up is not an admission: a rollout told otherwise would under-count \
             the users it is about to challenge"
        );
        assert_eq!(
            dry.would_act(),
            &Action::StepUp {
                acr: "mfa".to_owned()
            }
        );
    }

    /// `reason` SPEAKS FOR EVERY OUTCOME, so no caller has to reach for `why_denied` and
    /// print nothing next to an admission or a challenge.
    #[test]
    fn every_outcome_has_a_sentence() {
        let cases = [
            (Action::Allow, "allowed by rule r"),
            (Action::Deny, "denied by rule r"),
            (
                Action::StepUp {
                    acr: "mfa".to_owned(),
                },
                "rule r requires step-up to mfa",
            ),
        ];
        for (action, expected) in cases {
            let set = RuleSet::new(vec![rule("r", vec![], action)]);
            assert_eq!(set.explain(&facts()).reason(), expected);
        }

        // And the two no-rule shapes, which name no rule at all.
        assert_eq!(
            RuleSet::default().explain(&facts()).reason(),
            "denied because no rules are configured"
        );
    }

    /// THE FIRST OF TWO MATCHING RULES DECIDES, and the trace says so.
    ///
    /// The corpus previously had no request matching more than one rule, so the assertion
    /// that "the rules marked Matched" equals "the rule the decision names" compared at most
    /// one element and could not distinguish first-match from last-match. This makes the
    /// overlap explicit rather than relying on a corpus row to carry it.
    #[test]
    fn with_two_matching_rules_only_the_first_is_marked_matched() {
        let set = RuleSet::new(vec![
            deny("first", vec![Criterion::PathPrefix("/x".to_owned())]),
            allow("second", vec![Criterion::PathPrefix("/x".to_owned())]),
        ]);
        let request = RequestFacts {
            path: "/x/y".to_owned(),
            ..facts()
        };
        let explained = set.explain(&request);

        assert_eq!(explained.decision.matched.as_deref(), Some("first"));
        assert_eq!(
            explained.trace.rules,
            vec![
                RuleTrace {
                    rule: "first".to_owned(),
                    outcome: RuleOutcome::Matched,
                },
                RuleTrace {
                    rule: "second".to_owned(),
                    outcome: RuleOutcome::NotReached,
                },
            ],
            "the second rule matches the path too, and must be NotReached rather than Matched"
        );
    }
}
