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

use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;
use std::time::{Duration, Instant};

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
    ///
    /// # A rule carrying this action decides `Allow` once the request reaches the ACR
    ///
    /// "Admit only with a stronger authentication" is a condition, not a verdict, and the
    /// engine resolves it: a matching step-up rule whose ACR the request has ALREADY reached
    /// decides [`Action::Allow`], attributed to that rule.
    ///
    /// Without the resolution this action could not terminate. The caller is challenged,
    /// authenticates, returns with the stronger authentication, matches the SAME rule, and is
    /// challenged again, forever, because nothing in the rule set can observe that the
    /// challenge was met. That is not a hypothetical: the engine shipped with this action and
    /// with no fact describing the authentication a request arrives with, so every step-up
    /// rule an operator could write was an infinite redirect.
    ///
    /// The comparison is the step-up ladder's ([`crate::acr_satisfies`]) under the
    /// order the rule set carries, so a request that reached a STRONGER rung than the rule
    /// names satisfies it, and an unranked ACR satisfies only itself.
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
    /// The authentication the request ARRIVED with reaches this ACR floor.
    ///
    /// Compared through the step-up ladder ([`crate::acr_satisfies`]) under the
    /// order the rule set carries, so naming `pwd` is satisfied by an `mfa` session and a
    /// floor absent from the order is satisfied only by itself.
    ///
    /// A request carrying NO authentication context never satisfies this, whatever the floor,
    /// and an EMPTY floor is satisfied by nothing. Both are the refusing direction, and both
    /// match the rest of this vocabulary: an empty `PathPrefix` matches no path and an empty
    /// `Method` list matches no method, because a criterion that constrains nothing is
    /// written by leaving it out.
    ///
    /// # This is not the same thing as [`Action::StepUp`]
    ///
    /// The action OFFERS the caller a remedy; this criterion merely selects. A rule that
    /// should challenge a weakly authenticated caller uses the action. A rule that should
    /// simply not apply to one -- an `allow` that is only for strongly authenticated
    /// sessions, sitting above a broader `deny` -- uses this.
    AcrAtLeast(String),
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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
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
    /// The authentication context class the request ALREADY reached, absent when the caller
    /// is anonymous or the surface resolved none.
    ///
    /// # Derived, never asserted
    ///
    /// This is the ACHIEVED context: what the recorded authentication actually did, as
    /// [`crate::achieved_acr`] derives it from the session's method tokens. It is not
    /// a value the caller sends. A request-supplied ACR would let anyone answer the step-up
    /// challenge made of them by claiming to have met it, which is the whole of the
    /// requirement handed to the party it constrains.
    ///
    /// The field is public like the rest of [`RequestFacts`], so the guarantee lives at the
    /// surface that fills it in: [`crate::forward_auth::ForwardAuth::evaluate`] OVERWRITES
    /// it from the resolved identity exactly as it overwrites the subject, groups and roles,
    /// for the same reason -- one principal, so what the engine decides about and what the
    /// authentication established cannot disagree.
    pub acr: Option<String>,
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

    /// The reached authentication context, but only when there actually is one.
    ///
    /// An EMPTY acr is not an acr, for the reason `authenticated_subject` gives one field up:
    /// it is what a partially filled `RequestFacts` and a blank proxy header both produce,
    /// and treating it as a reached context would let it satisfy an equally empty floor.
    /// Every reader comes through here, so the question is answered once.
    fn achieved_acr(&self) -> Option<&str> {
        self.acr.as_deref().filter(|acr| !acr.is_empty())
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
#[derive(Debug, Clone)]
pub struct RuleSet {
    rules: Vec<Rule>,
    acr_order: Vec<String>,
}

impl Default for RuleSet {
    /// No rules, and the DEFAULT ladder rather than an empty one.
    ///
    /// Derived `Default` gave an empty order, which is not "no opinion": an empty order ranks
    /// nothing, so `acr_satisfies` falls back to exact string equality and an `mfa` session
    /// stops satisfying a `pwd` floor. A rule set built the short way would have enforced a
    /// different policy from one built through [`RuleSet::new`], silently and in the
    /// challenging direction.
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

impl RuleSet {
    /// Build a rule set from rules in evaluation order, ranking ACRs by the default ladder.
    #[must_use]
    pub fn new(rules: Vec<Rule>) -> Self {
        Self {
            rules,
            acr_order: crate::step_up::default_acr_order(),
        }
    }

    /// The same rules, ranking ACRs by a deployment's configured order (`oidc.acr_order`).
    ///
    /// Takes the order rather than reading it, because this crate's rule engine is consulted
    /// by surfaces that resolve configuration differently and two of them disagreeing about
    /// the ladder is a policy difference, not a detail.
    #[must_use]
    pub fn with_acr_order(mut self, order: Vec<String>) -> Self {
        self.acr_order = order;
        self
    }

    /// The ACR order these rules rank by, weakest first.
    #[must_use]
    pub fn acr_order(&self) -> &[String] {
        &self.acr_order
    }

    /// The rules, in evaluation order.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Which request facts these rules actually read.
    ///
    /// Used to narrow a decision cache key to exactly the inputs a decision depends on. See
    /// [`FactDependencies`] for why the narrowing has to be derived rather than chosen.
    ///
    /// The `match` below is exhaustive on purpose: a new [`Criterion`] does not compile
    /// until it declares what it reads, which is what stops a cache key silently omitting an
    /// input and handing one caller another caller's verdict.
    #[must_use]
    pub fn dependencies(&self) -> FactDependencies {
        let mut deps = FactDependencies::default();
        for rule in &self.rules {
            for criterion in &rule.criteria {
                match criterion {
                    Criterion::Method(_) => {
                        deps.fields.insert(FactField::Method);
                    }
                    Criterion::Host(_) => {
                        deps.fields.insert(FactField::Host);
                    }
                    Criterion::PathPrefix(_) | Criterion::PathMatches(_) => {
                        deps.fields.insert(FactField::Path);
                    }
                    Criterion::Header { name, .. } => {
                        deps.headers.insert(name.to_ascii_lowercase());
                    }
                    Criterion::Subject(check) => match check {
                        // A capture comes from a path pattern, so a rule reading one depends
                        // on the PATH as well as the subject. Missing this would let two
                        // requests with the same subject and different paths share an entry.
                        SubjectCheck::Is(_)
                        | SubjectCheck::Authenticated
                        | SubjectCheck::Anonymous => {
                            deps.fields.insert(FactField::Subject);
                        }
                        SubjectCheck::EqualsCapture(_) => {
                            deps.fields.insert(FactField::Subject);
                            deps.fields.insert(FactField::Path);
                        }
                        SubjectCheck::InGroup(_) => {
                            deps.fields.insert(FactField::Subject);
                            deps.fields.insert(FactField::Groups);
                        }
                        SubjectCheck::HasRole(_) => {
                            deps.fields.insert(FactField::Subject);
                            deps.fields.insert(FactField::Roles);
                        }
                    },
                    Criterion::AcrAtLeast(_) => {
                        deps.fields.insert(FactField::Acr);
                    }
                }
            }
            // THE ACTION READS A FACT TOO, and only this one does.
            //
            // Every other action is a constant: a rule that matches decides `Allow` or `Deny`
            // regardless of the request. A step-up rule does not -- it resolves to `Allow`
            // for a caller who has reached the ACR and challenges one who has not -- so the
            // reached ACR is an INPUT to the decision even when no criterion mentions it.
            //
            // Deriving dependencies from criteria alone was therefore a cache key missing an
            // input, which is the failure the comment above this method describes: two
            // requests differing only in how strongly they authenticated share one entry, and
            // the first caller through the door hands their `Allow` to every caller behind
            // them. The step-up requirement would be enforced for exactly one request per TTL.
            //
            // Matched exhaustively so a fifth action cannot be added without answering this.
            match &rule.action {
                Action::Allow | Action::Deny => {}
                Action::StepUp { .. } => {
                    deps.fields.insert(FactField::Acr);
                }
            }
        }
        deps
    }

    /// A fingerprint of these rules, used as a decision cache's generation.
    ///
    /// # Why not a counter
    ///
    /// It was a per-instance counter starting at zero, and that is wrong the moment the
    /// cache is SHARED, which is the case [`DecisionStore`] exists for. Two processes over
    /// one store both start at zero, so a replica holding revoked rules reads entries the
    /// old rules wrote and serves the revoked answer for a full TTL. A review measured
    /// exactly that: a replica constructed with deny rules served the previous replica's
    /// cached ALLOW. A restart is enough; a second replica is enough.
    ///
    /// A fingerprint has no such lifetime. The same rules produce the same value in every
    /// process and different rules a different one, so sharing is safe and a revocation is
    /// unreachable everywhere at once rather than only where it was made.
    ///
    /// Derived from the same rendering the traces use, so it covers every part of a rule a
    /// decision can depend on. A collision would need two rule sets to agree on 64 bits; the
    /// rules are operator-authored rather than attacker-chosen, and the consequence is a
    /// shared entry rather than a bypass.
    #[must_use]
    pub fn fingerprint(&self) -> u64 {
        use std::hash::{Hash, Hasher};

        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        // THE ORDER IS PART OF THE POLICY, so it is part of the generation. Two replicas
        // holding identical rules under different `oidc.acr_order` values resolve a step-up
        // differently -- one admits a session the other challenges -- and a shared store
        // would let the laxer replica's `Allow` answer the stricter one's request.
        self.acr_order.hash(&mut hasher);
        // Hashed first so that appending a rule cannot be absorbed by the concatenation of
        // the ones before it.
        self.rules.len().hash(&mut hasher);
        for rule in &self.rules {
            rule.name.hash(&mut hasher);
            rule.criteria.len().hash(&mut hasher);
            for criterion in &rule.criteria {
                // `describe` is exhaustive, so a new variant has to say how it renders
                // before this can silently stop distinguishing it.
                describe(criterion).hash(&mut hasher);
                // `describe` deliberately omits a header's configured VALUE, so hash it
                // here: two rules differing only in the value they require are different
                // rules and must not share a generation.
                if let Criterion::Header { value, .. } = criterion {
                    value.hash(&mut hasher);
                }
            }
            match &rule.action {
                Action::Allow => 0u8.hash(&mut hasher),
                Action::Deny => 1u8.hash(&mut hasher),
                Action::StepUp { acr } => {
                    2u8.hash(&mut hasher);
                    acr.hash(&mut hasher);
                }
            }
        }
        hasher.finish()
    }

    /// Decide `facts` against the set: the first rule whose criteria all hold.
    #[must_use]
    pub fn decide(&self, facts: &RequestFacts) -> Decision {
        self.walk(facts, &mut Silent)
    }

    /// The rule that explicitly REFUSES `facts`, for a consumer where the request is already
    /// authorized and these rules are an additional denial layer.
    ///
    /// # This reads the same rules with the OPPOSITE default, deliberately
    ///
    /// [`RuleSet::decide`] denies a request no rule matched, and the module documentation
    /// explains at length why: a forward-auth resource has no other gate, so a fall-through
    /// that admits is one forgotten rule away from an open door.
    ///
    /// Token issuance is not that. By the time a grant reaches a mint, the client has been
    /// authenticated, the grant validated and the subject's own authorization checked. These
    /// rules are what issue #154 calls "deny issuance by user/group/network" -- a DENY LIST
    /// layered on top. Reading `no_match` as a refusal there would mean that the moment an
    /// operator wrote a single forward-auth path rule, every token in the deployment stopped
    /// being issued, because a token request matches no path rule.
    ///
    /// So this is a SEPARATE entry point rather than a flag on `decide`. A flag is one
    /// forgotten argument away from a forward-auth check reading its fall-through as an
    /// admission, and that failure is silent and admits. A caller has to name which question
    /// it is asking, and the two names do not look alike.
    ///
    /// # A step-up is not a refusal here
    ///
    /// Only [`Action::Deny`] refuses. A matching [`Action::StepUp`] the request has not met
    /// describes a remedy a token endpoint cannot offer in this position -- the authentication
    /// already happened, and there is no caller to redirect. Treating it as a denial would
    /// refuse a grant for a reason the response could not express; the surfaces that CAN offer
    /// the remedy are the authorization request and the forward-auth check, which is where a
    /// step-up rule belongs. `decide` still returns it for them.
    /// # ONLY the rules that say something about WHO IS ASKING take part
    ///
    /// A rule carrying no criterion about the principal is not policy at this consumer, and
    /// skipping it is the difference between this being usable and being an outage.
    ///
    /// The first version excused only the IMPLICIT fall-through -- `decide` answers an
    /// unmatched request `(Deny, None)`, and reading the action alone would refuse it. A review
    /// showed that is not enough, because an operator writing the same default DOWN gets the
    /// opposite answer: `[[forward_auth.rules]] name = "deny the rest", action = "deny"` with
    /// no criteria matches everything (an empty criteria list is how a catch-all is written),
    /// so it arrives as `(Deny, Some("deny the rest"))` and refused every token in the
    /// deployment. That is the repository's own canonical shape -- the config crate's
    /// `a_well_formed_rule_list_is_accepted` ends with exactly it, this crate's forward-auth
    /// fixtures use `rule("default-deny", vec![], Action::Deny)`, and `validate_access_rule`
    /// steers operators toward it by refusing `path_prefix = "/"` with "a rule that applies to
    /// any path is written by omitting `path_prefix`".
    ///
    /// The filter also closes the other direction, which is the one that ADMITS. `Criterion::
    /// Host("")` equals the empty host these facts carry, and a `PathMatches` accepting the
    /// empty string matches the empty path, so a request-shaped `allow` could match first and
    /// shadow the `deny` an operator wrote below it. A rule that constrains nothing about the
    /// principal now shadows nothing either.
    ///
    /// A global "issue nothing" is still expressible and now has to be written as what it is:
    /// a deny naming `subject_state = "authenticated"`, which every issuance satisfies.
    #[must_use]
    pub fn refusal(&self, facts: &RequestFacts) -> Option<String> {
        let decision = self.walk_filtered(facts, &mut Silent, Self::constrains_the_principal);
        match (decision.action, decision.matched) {
            (Action::Deny, Some(rule)) => Some(rule),
            // A fall-through is `(Deny, None)`, and asking for the NAME as well as the action
            // is what separates it from a rule that denied.
            _ => None,
        }
    }

    /// The ACR the first matching rule DEMANDS of this principal, if any.
    ///
    /// The third consumer of one rule set (issue #154 criterion 4). The forward-auth check
    /// renders a step-up as a 401 challenge, and the issuance gate cannot offer a remedy at
    /// all; this is the surface that can actually run the ceremony, so what it needs from the
    /// rules is the REQUIREMENT rather than a verdict.
    ///
    /// # UNRESOLVED, unlike `decide`
    ///
    /// [`RuleSet::decide`] resolves a step-up the request has already met into an `Allow`,
    /// which is what makes a forward-auth rule terminate. Here that resolution would be the
    /// wrong shape twice over. The caller composes this floor with the request's `acr_values`,
    /// the per-client floor, the per-scope policy and the broker overlay through
    /// [`crate::step_up::AuthnRequirement::merge_stronger`], and it is THAT merged requirement
    /// the step-up machinery evaluates -- including the `max_age` half, which this engine
    /// cannot express. Handing it a verdict computed from the ACR alone would discard the age
    /// question and pre-empt a composition that knows more than this rule set does.
    ///
    /// # The same principal filter as `refusal`, for the same reason
    ///
    /// An authorization request names no resource path, so a rule constraining one would
    /// either never fire or fire on emptiness. What can honestly select here is who is asking
    /// and what they have already reached.
    #[must_use]
    pub fn step_up_floor(&self, facts: &RequestFacts) -> Option<String> {
        self.rules
            .iter()
            .filter(|rule| Self::constrains_the_principal(rule))
            .find(|rule| self.first_failing_criterion(rule, facts).is_none())
            .and_then(|rule| match &rule.action {
                Action::StepUp { acr } => Some(acr.clone()),
                // FIRST MATCH WINS, exactly as everywhere else: an `allow` or a `deny` above a
                // step-up rule means the step-up rule was not reached, and inventing a floor
                // from a later rule would make this the one reading where order does not hold.
                Action::Allow | Action::Deny => None,
            })
    }

    /// Whether `rule` says anything about the principal, as opposed to the request.
    ///
    /// The match is exhaustive so a new [`Criterion`] cannot be added without deciding which
    /// side of this line it is on. Getting that wrong in the request direction makes a rule
    /// inert at a consumer that should honour it; getting it wrong in the principal direction
    /// is the outage above.
    fn constrains_the_principal(rule: &Rule) -> bool {
        rule.criteria.iter().any(|criterion| match criterion {
            Criterion::Subject(_) | Criterion::AcrAtLeast(_) => true,
            Criterion::Method(_)
            | Criterion::Host(_)
            | Criterion::PathPrefix(_)
            | Criterion::PathMatches(_)
            | Criterion::Header { .. } => false,
        })
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

    /// The index of the first criterion of `rule` that does not hold, or `None` when it
    /// matches.
    ///
    /// Factored out because [`RuleSet::step_up_floor`] asks the same question and must not
    /// answer it differently. Two implementations of "does this rule match" is how a consumer
    /// ends up acting on a rule the engine did not select, and this file already says exactly
    /// that about its trace.
    ///
    /// Captures are per-rule: a fresh map each call, so one rule can never read what another
    /// rule's pattern bound. It stops at the FIRST failure, preserving the short-circuit that
    /// `all()` gave us, which is also the right answer for a trace -- the criteria after it
    /// never ran, so claiming anything about them would be a guess.
    fn first_failing_criterion(&self, rule: &Rule, facts: &RequestFacts) -> Option<usize> {
        let mut captures: HashMap<String, String> = HashMap::new();
        rule.criteria
            .iter()
            .position(|criterion| !matches(criterion, facts, &mut captures, &self.acr_order))
    }

    /// The single implementation. `decide`, `explain` and `dry_run` all come through here.
    fn walk<R: Recorder>(&self, facts: &RequestFacts, recorder: &mut R) -> Decision {
        self.walk_filtered(facts, recorder, |_| true)
    }

    /// The same walk over a SUBSET of the rules.
    ///
    /// One implementation with a predicate rather than a second loop in [`RuleSet::refusal`].
    /// Two implementations of one decision is how a consumer ends up enforcing something the
    /// engine does not do, and this file already says that about its trace.
    ///
    /// A skipped rule is skipped entirely: it cannot decide and it cannot shadow a later rule
    /// by matching first. That is the point -- see [`RuleSet::refusal`].
    fn walk_filtered<R: Recorder>(
        &self,
        facts: &RequestFacts,
        recorder: &mut R,
        eligible: fn(&Rule) -> bool,
    ) -> Decision {
        let mut decided: Option<Decision> = None;
        for rule in self.rules.iter().filter(|rule| eligible(rule)) {
            if decided.is_some() {
                // Only a recording walk continues past the decision, and only to mark the
                // rules that were never consulted. A plain `decide` returns below, so it
                // does exactly the work it did before tracing existed.
                recorder.not_reached(rule);
                continue;
            }
            if let Some(index) = self.first_failing_criterion(rule, facts) {
                recorder.failed(rule, index);
                continue;
            }
            recorder.matched(rule);
            let decision = Decision {
                action: self.resolve(&rule.action, facts),
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

    /// The action a matching rule actually decides, given what the request authenticated as.
    ///
    /// Only [`Action::StepUp`] is not already a verdict; see its documentation for why
    /// resolving it here is what lets a step-up rule terminate.
    ///
    /// Placed on the walk rather than at each caller deliberately. `decide`, `explain` and
    /// `dry_run` all come through `walk`, and criterion 4 asks that the same rules gate a
    /// forward-auth resource, an OIDC issuance and a step-up requirement -- three surfaces.
    /// A resolution performed by the caller is a resolution five callers can each get wrong,
    /// and the wrong answers differ: one loops, one admits.
    fn resolve(&self, action: &Action, facts: &RequestFacts) -> Action {
        match action {
            Action::StepUp { acr }
                if facts.achieved_acr().is_some_and(|achieved| {
                    crate::step_up::acr_satisfies(achieved, acr, &self.acr_order)
                }) =>
            {
                Action::Allow
            }
            other => other.clone(),
        }
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
        Criterion::AcrAtLeast(floor) => format!("authentication reaches {floor}"),
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
    acr_order: &[String],
) -> bool {
    match criterion {
        // AN ABSENT FLOOR AND AN ABSENT CONTEXT BOTH REFUSE, and the two `is_some_and`s are
        // what says so: no reached context fails whatever the floor, and `acr_satisfies`
        // answers false for an empty floor because an empty string is in no order and equals
        // no reached value (`achieved_acr` has already excluded the empty one).
        Criterion::AcrAtLeast(floor) => facts
            .achieved_acr()
            .is_some_and(|achieved| crate::step_up::acr_satisfies(achieved, floor, acr_order)),
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

// ===========================================================================
// Criterion 6: cached decisions with bounded TTLs, invalidation on a rule
// change, and full evaluation when the cache cannot answer.
// ===========================================================================

/// Which request facts a rule set actually reads.
///
/// # Why this is DERIVED and not hand-written
///
/// A decision cache is only correct if its key covers every input the decision depends on.
/// Key on too little and two different requests collide, and one caller is handed the other
/// caller's verdict: a cross-request authorization failure, silent, and in whichever
/// direction the first request happened to go.
///
/// Keying on the whole of [`RequestFacts`] is correct and nearly useless, because the facts
/// differ on every request and nothing would ever hit. So the key is narrowed to exactly
/// what the configured rules consult, computed by walking the criteria. The narrowing is
/// therefore a consequence of the rules rather than a guess about them, and a rule set that
/// reads nothing collapses to one entry, which is right.
///
/// [`RuleSet::dependencies`] builds this with an exhaustive `match`, so a new [`Criterion`]
/// cannot be added without an arm.
///
/// # What exhaustiveness does NOT buy
///
/// An earlier version of this comment called that "the whole safety argument: the compiler,
/// not a reviewer's memory". It is not. Exhaustiveness forces an arm to EXIST; it says
/// nothing about the arm being right, and a review demonstrated the gap by adding a
/// criterion with an empty arm, which compiled, passed the suite, and let two requests that
/// differ only in the new fact share a key.
///
/// The compiler-forced half is therefore paired with
/// `every_criterion_contributes_the_facts_it_reads`, which states the expected facts in a
/// SECOND exhaustive match written independently of this one. Two independent statements of
/// the same fact have to agree, and a new variant does not compile until both are written.
///
/// The other half of the risk is not here at all: [`CachedRuleSet::key_for`] is a second
/// hand-written reading of what each fact MEANS -- case-insensitivity for method and host,
/// every matching entry for a header, the empty-subject normalization -- and nothing ties it
/// to `matches`. Three of those four readings were wrong when this landed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FactDependencies {
    /// The single-valued facts that are read. A SET rather than a row of booleans, so
    /// adding a fact does not widen a struct nobody re-reads, and so the key can iterate
    /// exactly what matters in a stable order.
    fields: BTreeSet<FactField>,
    /// Lowercased header names, so the set matches the case-insensitive comparison.
    headers: BTreeSet<String>,
}

/// One single-valued request fact a rule can read.
///
/// `Ord` so a [`DecisionKey`] enumerates fields in a stable order: a key whose field order
/// depended on iteration order would make two equal requests produce unequal keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FactField {
    /// The request method.
    Method,
    /// The host.
    Host,
    /// The path.
    Path,
    /// The authenticated subject.
    Subject,
    /// The subject's groups.
    Groups,
    /// The subject's roles.
    Roles,
    /// The authentication context class the request reached.
    Acr,
}

impl FactDependencies {
    /// Whether nothing at all is read, so every request shares one cache entry.
    #[must_use]
    pub fn reads_nothing(&self) -> bool {
        self.fields.is_empty() && self.headers.is_empty()
    }

    /// Whether `field` is read by the rules this was derived from.
    #[must_use]
    pub fn reads(&self, field: FactField) -> bool {
        self.fields.contains(&field)
    }

    /// The header names that are read, lowercased.
    pub fn headers(&self) -> impl Iterator<Item = &str> {
        self.headers.iter().map(String::as_str)
    }
}

/// The cache key for one request under one rule set.
///
/// Carries the rule set's generation, so a rule change cannot be answered from an entry
/// computed under the previous rules: the old entries are not evicted, they become
/// unreachable, which is the same thing and needs no sweep.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DecisionKey {
    generation: u64,
    /// `(field, value)` for every single-valued fact the rules read, in `FactField` order.
    ///
    /// Only the fields that are READ appear, so a fact no rule consults cannot split the
    /// cache. The value is an `Option` because a fact can be read and absent, and those two
    /// states must not collide: a subject that is set and one that is absent are different
    /// callers. An EMPTY subject is not a third class -- it is read through
    /// `RequestFacts::authenticated_subject`, the same accessor the engine decides with, so
    /// the key has exactly the classes the rules can tell apart.
    fields: Vec<(FactField, Option<String>)>,
    /// `(name, values)` for every header name the rules read: ALL values carried under any
    /// case-spelling of that name, sorted.
    ///
    /// A single value here was a defect, not a simplification. `matches` decides with
    /// `.any()` over every entry whose name matches case-insensitively, while this built the
    /// key with `.find()`, which picks ONE arbitrarily from a `HashMap`. A request carrying
    /// two spellings of one header was therefore evaluated against both and stored under a
    /// key belonging to a different equivalence class, so an ordinary later request with a
    /// single correctly-spelled header was served that stored ALLOW. A review measured
    /// 18089 wrong answers in 640000 comparisons, and 112 unauthorized admissions in 200
    /// constructions of one identical request.
    ///
    /// Sorted, because a `HashMap` has no order and a key that depended on one would not be
    /// a function of its input.
    headers: Vec<(String, Vec<String>)>,
    /// Sorted membership, when read. Absent when no rule consults it.
    groups: Option<Vec<String>>,
    /// Sorted membership, when read.
    roles: Option<Vec<String>>,
}

/// What a cache answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheOutcome {
    /// A live entry.
    Hit(Decision),
    /// No entry, or one past its TTL.
    Miss,
    /// The cache could not answer at all.
    ///
    /// Distinct from [`CacheOutcome::Miss`] on purpose: a miss is the cache working, and an
    /// outage is the cache being unavailable. They lead to the same evaluation but they are
    /// different operational events, and a metric that cannot tell them apart cannot show an
    /// operator that their cache is down.
    Unavailable,
}

/// Somewhere decisions can be remembered.
///
/// A trait rather than a concrete map, because criterion 6 requires behaviour under a cache
/// OUTAGE, and an in-process map cannot have one. A remote cache can, and this is the seam
/// where that is representable and testable today.
pub trait DecisionStore {
    /// Look `key` up as of `now`.
    fn get(&self, key: &DecisionKey, now: Instant) -> CacheOutcome;
    /// Remember `decision` for `key` as of `now`. Failures are silent by contract: a cache
    /// that cannot store must never turn into a request that cannot be served.
    fn put(&self, key: DecisionKey, decision: Decision, now: Instant);
}

/// A rule set with a decision cache in front of it.
///
/// # The two properties that make this safe
///
/// **A cached answer is never stale past the TTL.** Entries carry the instant they were
/// stored and are ignored once older than `ttl`, so the worst-case age of any served
/// decision is bounded by a number the operator set.
///
/// **A rule change is immediate, not TTL-bounded.** The generation is part of the key, so
/// after [`CachedRuleSet::replace_rules`] no request can reach an entry computed under the
/// old rules. The bound criterion 6 asks about (TTL plus the invalidation SLO) is therefore
/// the TTL for an unchanged rule set and zero for a changed one.
pub struct CachedRuleSet<S> {
    rules: RuleSet,
    dependencies: FactDependencies,
    generation: u64,
    store: S,
}

impl<S: DecisionStore> CachedRuleSet<S> {
    /// Wrap `rules` with `store`.
    #[must_use]
    pub fn new(rules: RuleSet, store: S) -> Self {
        let dependencies = rules.dependencies();
        let generation = rules.fingerprint();
        Self {
            rules,
            dependencies,
            generation,
            store,
        }
    }

    /// The rule set being cached.
    #[must_use]
    pub fn rules(&self) -> &RuleSet {
        &self.rules
    }

    /// What the current rules read.
    #[must_use]
    pub fn dependencies(&self) -> &FactDependencies {
        &self.dependencies
    }

    /// The backing store, for metrics and for health reporting.
    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Swap the rules, making every entry computed under the old ones unreachable.
    pub fn replace_rules(&mut self, rules: RuleSet) {
        self.dependencies = rules.dependencies();
        self.generation = rules.fingerprint();
        self.rules = rules;
    }

    /// The key `facts` presents under the current rules.
    #[must_use]
    pub fn key_for(&self, facts: &RequestFacts) -> DecisionKey {
        let deps = &self.dependencies;
        // BTreeSet iteration is sorted, so the field order is stable and two equal requests
        // cannot produce unequal keys through iteration order alone.
        let fields = deps
            .fields
            .iter()
            .filter_map(|field| {
                let value = match field {
                    // LOWERCASED, because `matches` compares these with
                    // `eq_ignore_ascii_case`. Keying on the raw bytes splits the cache for
                    // callers the engine cannot tell apart, which is the harmless direction
                    // but makes the feature pointless, and it is a second reading of the
                    // same field.
                    FactField::Method => Some(facts.method.to_ascii_lowercase()),
                    FactField::Host => Some(facts.host.to_ascii_lowercase()),
                    // NOT lowercased: a path is compared exactly.
                    FactField::Path => Some(facts.path.clone()),
                    // Through the SAME accessor the engine decides with, so an empty
                    // subject is one caller with `None` rather than a third class the key
                    // invents. The file documented both readings at once.
                    FactField::Subject => facts.authenticated_subject().map(str::to_owned),
                    // Through the SAME accessor again: an empty acr is the absent one.
                    FactField::Acr => facts.achieved_acr().map(str::to_owned),
                    // Carried in their own fields below, because they are lists.
                    FactField::Groups | FactField::Roles => return None,
                };
                Some((*field, value))
            })
            .collect();

        DecisionKey {
            generation: self.generation,
            fields,
            // EVERY value under any case-spelling of the name, matching what `matches`
            // consults. Taking one arbitrarily is the collision described on the field.
            headers: deps
                .headers
                .iter()
                .map(|name| {
                    let mut values: Vec<String> = facts
                        .headers
                        .iter()
                        .filter(|(actual, _)| actual.eq_ignore_ascii_case(name))
                        .map(|(_, value)| value.clone())
                        .collect();
                    values.sort_unstable();
                    (name.clone(), values)
                })
                .collect(),
            groups: deps.reads(FactField::Groups).then(|| {
                let mut sorted = facts.groups.clone();
                // Sorted, because membership is a SET: the same caller presented in a
                // different order is the same caller and must not miss its own entry.
                sorted.sort_unstable();
                sorted
            }),
            roles: deps.reads(FactField::Roles).then(|| {
                let mut sorted = facts.roles.clone();
                sorted.sort_unstable();
                sorted
            }),
        }
    }

    /// Decide, consulting the cache.
    ///
    /// A [`CacheOutcome::Unavailable`] falls through to full evaluation exactly as a miss
    /// does. A cache is an optimisation, and an optimisation that can refuse a request is a
    /// liability: the answer is always computable from the rules and the facts.
    pub fn decide(&self, facts: &RequestFacts, now: Instant) -> CachedDecision {
        let key = self.key_for(facts);
        match self.store.get(&key, now) {
            CacheOutcome::Hit(decision) => CachedDecision {
                decision,
                cached: true,
                store_available: true,
            },
            CacheOutcome::Miss => {
                let decision = self.rules.decide(facts);
                self.store.put(key, decision.clone(), now);
                CachedDecision {
                    decision,
                    cached: false,
                    store_available: true,
                }
            }
            CacheOutcome::Unavailable => CachedDecision {
                decision: self.rules.decide(facts),
                cached: false,
                store_available: false,
            },
        }
    }
}

/// A decision, plus where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedDecision {
    /// The answer, identical either way.
    pub decision: Decision,
    /// Whether it was served from the cache.
    pub cached: bool,
    /// Whether the cache was reachable. `false` means the answer was computed and the
    /// operator has a cache outage worth alerting on.
    pub store_available: bool,
}

/// An in-process [`DecisionStore`] with a bounded TTL.
///
/// Never reports [`CacheOutcome::Unavailable`], because an in-process map has no outage to
/// report. Testing the outage path needs a store that can fail, which is exactly why
/// [`DecisionStore`] is a trait.
pub struct MemoryStore {
    ttl: Duration,
    max_entries: usize,
    entries: Mutex<HashMap<DecisionKey, (Decision, Instant)>>,
}

/// How many decisions a [`MemoryStore`] retains before it reclaims.
///
/// Without a ceiling the map grows with the request stream. Any rule set reading the path
/// puts it in the key, and on a forward-auth surface the path is unauthenticated attacker
/// input, so the growth is driven by exactly the traffic this sits in front of. A review
/// measured 20000 entries retained after 20000 distinct paths on a one-second TTL: expired
/// entries were ignored on read and kept forever.
pub const DEFAULT_MAX_DECISIONS: usize = 100_000;

impl MemoryStore {
    /// A store whose entries are ignored once older than `ttl`.
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            max_entries: DEFAULT_MAX_DECISIONS,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Override the entry ceiling. Mainly for tests, which cannot drive 100k distinct keys.
    #[must_use]
    pub fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = max_entries.max(1);
        self
    }

    /// How many entries are held, live or not.
    ///
    /// # Panics
    ///
    /// Panics only if the internal lock is poisoned.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.lock().expect("decision cache lock").len()
    }

    /// Whether the store holds nothing.
    ///
    /// # Panics
    ///
    /// Panics only if the internal lock is poisoned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl DecisionStore for MemoryStore {
    fn get(&self, key: &DecisionKey, now: Instant) -> CacheOutcome {
        let entries = self.entries.lock().expect("decision cache lock");
        let Some((decision, stored)) = entries.get(key) else {
            return CacheOutcome::Miss;
        };
        // A backwards clock reads as EXPIRED rather than fresh, so the failure direction is
        // recomputing an answer we already had, never serving one past its bound.
        //
        // This said exactly that while doing the opposite. `saturating_duration_since`
        // returns ZERO when the entry is stamped after `now`, i.e. age zero, i.e. FRESH --
        // so an entry stamped in the future was served forever. A review measured six hits
        // out of six across a simulated year on a thirty-second TTL. `checked_duration_since`
        // returns `None` instead, which is what makes the sentence above true.
        let Some(age) = now.checked_duration_since(*stored) else {
            return CacheOutcome::Miss;
        };
        if age >= self.ttl {
            return CacheOutcome::Miss;
        }
        CacheOutcome::Hit(decision.clone())
    }

    fn put(&self, key: DecisionKey, decision: Decision, now: Instant) {
        let mut entries = self.entries.lock().expect("decision cache lock");
        if entries.len() >= self.max_entries {
            // Expired entries are free to drop: they are already ignored on read, so
            // removing one changes no answer. This is the exact pass that was missing, and
            // it is enough whenever the TTL is doing its job.
            entries.retain(|_, (_, stored)| {
                now.checked_duration_since(*stored)
                    .is_some_and(|age| age < self.ttl)
            });
        }
        if entries.len() >= self.max_entries {
            // Everything is live and something still has to go. Dropping a LIVE entry costs
            // only a recomputation, never a wrong answer, because the decision is always
            // derivable from the rules and the facts.
            //
            // OLDEST FIRST, rather than clearing.
            //
            // A consequence worth recording: once the fallback prefers the oldest, the
            // expired-entry pass above stops being a separate CORRECTNESS property, because
            // expired entries are also the oldest and this pass would reclaim them anyway.
            // Disabling that pass leaves every test green, and that is the right answer
            // rather than a gap: what it still buys is avoiding this sort on the common
            // path, which is a timing difference, not a different answer. The bound itself
            // is pinned by `the_store_does_not_grow_without_bound`, which fails when BOTH
            // passes are removed. Clearing is simpler and was what this did,
            // and it throws away the newest entries too -- precisely the ones most likely to
            // be asked for again. The oldest are also the closest to expiring, so this is
            // the same preference the pass above has, continued past the point where it runs
            // out of free choices.
            let mut by_age: Vec<(DecisionKey, Instant)> = entries
                .iter()
                .map(|(key, (_, stored))| (key.clone(), *stored))
                .collect();
            by_age.sort_by_key(|(_, stored)| *stored);
            let excess = entries.len() + 1 - self.max_entries;
            for (key, _) in by_age.into_iter().take(excess) {
                entries.remove(&key);
            }
        }
        entries.insert(key, (decision, now));
    }
}

#[cfg(test)]
mod tests {
    use ironauth_env::Clock;

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
            // THE SIXTH CRITERION TYPE. Without it this set covered five of six, while the
            // doc above and on `corpus_cases` both said every variant appeared -- so the new
            // criterion never went through composition with another criterion, never appeared
            // in a trace, and never took part in the first-match ordering the corpus exists
            // to pin. Placed above its own catch-all for the same reason the step-up row is.
            allow(
                "vault-for-strong-sessions",
                vec![
                    Criterion::PathPrefix("/vault".to_owned()),
                    Criterion::AcrAtLeast(crate::step_up::canonical_step_up_acr("mfa")),
                ],
            ),
            deny(
                "vault-otherwise",
                vec![Criterion::PathPrefix("/vault".to_owned())],
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
                name: "a strong session reaches the vault through the floor above the deny",
                facts: RequestFacts {
                    path: "/vault/keys".to_owned(),
                    subject: Some("alice".to_owned()),
                    acr: Some(crate::step_up::canonical_step_up_acr("mfa")),
                    ..facts()
                },
                expect: Some("vault-for-strong-sessions"),
                action: Action::Allow,
            },
            Case {
                name: "the same request with a password session falls to the deny below it",
                facts: RequestFacts {
                    path: "/vault/keys".to_owned(),
                    subject: Some("alice".to_owned()),
                    acr: Some(crate::step_up::canonical_step_up_acr("pwd")),
                    ..facts()
                },
                expect: Some("vault-otherwise"),
                action: Action::Deny,
            },
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

    // -----------------------------------------------------------------------
    // Criterion 6: bounded TTLs, invalidation on a rule change, and full
    // evaluation when the cache cannot answer.
    // -----------------------------------------------------------------------

    /// A store that can be switched off, so the OUTAGE path is reachable in a test.
    struct FlakyStore {
        inner: MemoryStore,
        up: std::sync::atomic::AtomicBool,
        puts: std::sync::atomic::AtomicUsize,
    }

    impl FlakyStore {
        fn new(ttl: Duration) -> Self {
            Self {
                inner: MemoryStore::new(ttl),
                up: std::sync::atomic::AtomicBool::new(true),
                puts: std::sync::atomic::AtomicUsize::new(0),
            }
        }
        fn set_up(&self, up: bool) {
            self.up.store(up, std::sync::atomic::Ordering::SeqCst);
        }
        fn is_up(&self) -> bool {
            self.up.load(std::sync::atomic::Ordering::SeqCst)
        }
        fn puts(&self) -> usize {
            self.puts.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl DecisionStore for FlakyStore {
        fn get(&self, key: &DecisionKey, now: Instant) -> CacheOutcome {
            if self.is_up() {
                self.inner.get(key, now)
            } else {
                CacheOutcome::Unavailable
            }
        }
        fn put(&self, key: DecisionKey, decision: Decision, now: Instant) {
            self.puts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.is_up() {
                self.inner.put(key, decision, now);
            }
        }
    }

    fn admin_rules() -> RuleSet {
        RuleSet::new(vec![allow(
            "admins",
            vec![
                Criterion::PathPrefix("/admin".to_owned()),
                Criterion::Subject(SubjectCheck::HasRole("admin".to_owned())),
            ],
        )])
    }

    /// The instant `secs` after a fixed origin.
    ///
    /// The origin comes from a `ManualClock` rather than from the system clock, because the
    /// `time-via-env` invariant forbids reading the clock directly and is right to: a test
    /// that sleeps to advance time is slow and flaky, and one that samples the real clock
    /// twice is measuring the machine. A manual clock never advances on its own, so this is
    /// a constant origin and every instant below is arithmetic on it.
    fn at(secs: u64) -> Instant {
        TEST_CLOCK.monotonic() + Duration::from_secs(secs)
    }

    static TEST_CLOCK: std::sync::LazyLock<ironauth_env::ManualClock> =
        std::sync::LazyLock::new(ironauth_env::ManualClock::default);

    /// THE KEY COVERS EVERY FACT THE RULES READ.
    ///
    /// This is the property the whole design rests on. Key on too little and two different
    /// callers collide, and one is handed the other's verdict: a cross-request authorization
    /// failure, silent, in whichever direction the first request happened to go.
    ///
    /// Driven per criterion rather than by a hand-written list, so a criterion that stops
    /// contributing its fact is caught here.
    #[test]
    fn every_criterion_contributes_the_facts_it_reads() {
        /// The facts a criterion reads, stated INDEPENDENTLY of `RuleSet::dependencies`.
        ///
        /// A second exhaustive match, not a hand-written table. The table it replaced had
        /// ten rows and a doc claiming it was "driven per criterion"; a new variant simply
        /// got no row, so a criterion could declare nothing and nothing would notice. Now a
        /// new variant does not compile until it is written down twice, and the two
        /// statements have to agree.
        fn expected(criterion: &Criterion) -> Vec<FactField> {
            match criterion {
                Criterion::Method(_) => vec![FactField::Method],
                Criterion::Host(_) => vec![FactField::Host],
                Criterion::PathPrefix(_) | Criterion::PathMatches(_) => vec![FactField::Path],
                // Carried by name rather than as a `FactField`; checked separately below.
                Criterion::Header { .. } => vec![],
                Criterion::Subject(check) => match check {
                    SubjectCheck::Is(_) | SubjectCheck::Authenticated | SubjectCheck::Anonymous => {
                        vec![FactField::Subject]
                    }
                    // A capture comes from a path pattern, so this reads the path too.
                    SubjectCheck::EqualsCapture(_) => vec![FactField::Subject, FactField::Path],
                    SubjectCheck::InGroup(_) => vec![FactField::Subject, FactField::Groups],
                    SubjectCheck::HasRole(_) => vec![FactField::Subject, FactField::Roles],
                },
                Criterion::AcrAtLeast(_) => vec![FactField::Acr],
            }
        }

        let every_criterion = vec![
            Criterion::Method(vec!["GET".to_owned()]),
            Criterion::Host("h".to_owned()),
            Criterion::PathPrefix("/p".to_owned()),
            Criterion::PathMatches(Regex::new("^/p$").expect("pattern")),
            Criterion::AcrAtLeast("mfa".to_owned()),
            Criterion::Header {
                name: "X-Service".to_owned(),
                value: "v".to_owned(),
            },
            Criterion::Subject(SubjectCheck::Is("s".to_owned())),
            Criterion::Subject(SubjectCheck::Authenticated),
            Criterion::Subject(SubjectCheck::Anonymous),
            Criterion::Subject(SubjectCheck::EqualsCapture("c".to_owned())),
            Criterion::Subject(SubjectCheck::InGroup("g".to_owned())),
            Criterion::Subject(SubjectCheck::HasRole("r".to_owned())),
        ];

        for criterion in every_criterion {
            let rendered = describe(&criterion);
            let wanted = expected(&criterion);
            let deps = RuleSet::new(vec![allow("r", vec![criterion])]).dependencies();
            // BOTH DIRECTIONS AT ONCE, by comparing the SETS.
            //
            // This was a positive loop over `wanted` followed by a negative loop over a
            // hand-written list of every `FactField`. That second list is what fell behind:
            // `FactField::Acr` was added to the enum and not to it, so over-declaration of the
            // new fact -- a criterion splitting the cache on something it does not read -- was
            // unguarded, and a list written to catch a list falling behind had fallen behind.
            //
            // Comparing the sets needs no list. A variant added to the enum is covered the
            // moment `expected` names it, which the compiler already forces.
            assert_eq!(
                deps.fields,
                wanted.iter().copied().collect::<BTreeSet<FactField>>(),
                "{rendered}: the declared facts and the facts it reads disagree. Missing one \
                 makes two requests differing only in it share a cache entry; declaring one \
                 it does not read splits the cache for callers the engine cannot tell apart"
            );
        }

        // Headers are keyed by name, lowercased to match the case-insensitive comparison.
        let set = RuleSet::new(vec![allow(
            "r",
            vec![Criterion::Header {
                name: "X-Service".to_owned(),
                value: "v".to_owned(),
            }],
        )]);
        assert_eq!(
            set.dependencies().headers().collect::<Vec<_>>(),
            vec!["x-service"]
        );
    }

    /// TWO CALLERS THE RULES CAN TELL APART MUST NOT SHARE A CACHE ENTRY.
    ///
    /// The end-to-end version of the property above: an admin and a non-admin hitting the
    /// same path must get their own answers, not each other's.
    #[test]
    fn two_callers_with_different_roles_do_not_share_an_entry() {
        let cached = CachedRuleSet::new(admin_rules(), MemoryStore::new(Duration::from_secs(60)));
        let admin = RequestFacts {
            path: "/admin/keys".to_owned(),
            subject: Some("usr_1".to_owned()),
            roles: vec!["admin".to_owned()],
            ..facts()
        };
        let guest = RequestFacts {
            roles: vec!["guest".to_owned()],
            ..admin.clone()
        };

        assert_ne!(
            cached.key_for(&admin),
            cached.key_for(&guest),
            "a rule reading roles must put roles in the key"
        );

        let first = cached.decide(&admin, at(0));
        assert_eq!(first.decision.action, Action::Allow);
        let second = cached.decide(&guest, at(0));
        assert_eq!(
            second.decision.action,
            Action::Deny,
            "the guest must not be served the admin's cached admission"
        );
        assert!(
            !second.cached,
            "and it must be a miss, not a hit on the wrong key"
        );
    }

    /// A FACT THE RULES DO NOT READ IS NOT IN THE KEY, so the cache actually hits.
    ///
    /// The counterweight to the test above: keying on the whole of `RequestFacts` would be
    /// trivially safe and would never hit, because the facts differ on every request.
    #[test]
    fn a_fact_no_rule_reads_does_not_split_the_cache() {
        let cached = CachedRuleSet::new(admin_rules(), MemoryStore::new(Duration::from_secs(60)));
        let one = RequestFacts {
            path: "/admin/keys".to_owned(),
            subject: Some("usr_1".to_owned()),
            roles: vec!["admin".to_owned()],
            host: "a.example.com".to_owned(),
            ..facts()
        };
        // Same everything the rules read; a different host, which they do not.
        let two = RequestFacts {
            host: "b.example.com".to_owned(),
            ..one.clone()
        };

        assert_eq!(cached.key_for(&one), cached.key_for(&two));
        assert!(!cached.decide(&one, at(0)).cached);
        assert!(
            cached.decide(&two, at(0)).cached,
            "a fact no rule consults must not split the cache"
        );
    }

    /// GROUP AND ROLE ORDER DOES NOT CHANGE THE KEY. Membership is a set.
    #[test]
    fn membership_order_does_not_split_the_cache() {
        let set = RuleSet::new(vec![allow(
            "eng",
            vec![Criterion::Subject(SubjectCheck::InGroup("eng".to_owned()))],
        )]);
        let cached = CachedRuleSet::new(set, MemoryStore::new(Duration::from_secs(60)));
        let one = RequestFacts {
            subject: Some("u".to_owned()),
            groups: vec!["eng".to_owned(), "ops".to_owned()],
            ..facts()
        };
        let two = RequestFacts {
            groups: vec!["ops".to_owned(), "eng".to_owned()],
            ..one.clone()
        };
        assert_eq!(
            cached.key_for(&one),
            cached.key_for(&two),
            "the same caller presented in a different order is the same caller"
        );
    }

    /// AN ABSENT HEADER IS NOT THE SAME AS A PRESENT ONE.
    ///
    /// This test was written for a hazard that does not exist, and a review proved it: the
    /// header NAME is in the key structurally, so dropping an absent entry removes a pair
    /// and can never make two different requests equal. The mutant that skipped absent
    /// headers survived this test, which passed identically either way.
    ///
    /// It is kept because the property it asserts is still worth holding -- a request
    /// carrying a header the rules read must not share a key with one that lacks it -- and
    /// because the REAL collision in this area was the opposite shape: two case-spellings of
    /// one name, covered by
    /// `two_spellings_of_one_header_cannot_poison_another_callers_entry`.
    #[test]
    fn a_missing_header_does_not_share_a_key_with_a_present_one() {
        let set = RuleSet::new(vec![allow(
            "svc",
            vec![Criterion::Header {
                name: "X-Service".to_owned(),
                value: "billing".to_owned(),
            }],
        )]);
        let cached = CachedRuleSet::new(set, MemoryStore::new(Duration::from_secs(60)));

        let without = facts();
        let mut with = facts();
        with.headers
            .insert("x-service".to_owned(), "billing".to_owned());

        assert_ne!(cached.key_for(&without), cached.key_for(&with));
        assert_eq!(cached.decide(&without, at(0)).decision.action, Action::Deny);
        let allowed = cached.decide(&with, at(0));
        assert_eq!(
            allowed.decision.action,
            Action::Allow,
            "the header-bearing request must not inherit the bare request's denial"
        );
    }

    /// THE TTL BOUNDS HOW STALE A SERVED DECISION CAN BE.
    #[test]
    fn an_entry_is_not_served_past_its_ttl() {
        let ttl = Duration::from_secs(30);
        let cached = CachedRuleSet::new(admin_rules(), MemoryStore::new(ttl));
        let request = RequestFacts {
            path: "/admin/keys".to_owned(),
            subject: Some("u".to_owned()),
            roles: vec!["admin".to_owned()],
            ..facts()
        };

        assert!(!cached.decide(&request, at(0)).cached, "first call fills");
        assert!(
            cached.decide(&request, at(29)).cached,
            "inside the TTL it is served"
        );
        assert!(
            !cached.decide(&request, at(30)).cached,
            "AT the TTL it is already too old: the bound is exclusive"
        );

        // That miss REFILLED the entry at t=30, so the window restarts from there. An
        // earlier version of this test asserted a miss at t=31 and failed; the TEST was
        // wrong. A miss that did not refill would mean every request past the first TTL
        // recomputes forever, which is a cache that stops being one.
        assert!(
            cached.decide(&request, at(59)).cached,
            "the miss at 30 refilled, so 29s later is inside the NEW window"
        );
        assert!(
            !cached.decide(&request, at(60)).cached,
            "and that window expires exactly one TTL after the refill"
        );
    }

    /// A RULE CHANGE TAKES EFFECT IMMEDIATELY, not after the TTL.
    ///
    /// The generation is part of the key, so entries computed under the old rules are not
    /// evicted, they become unreachable. Criterion 6's "TTL plus the invalidation SLO" is
    /// therefore the TTL for unchanged rules and ZERO for changed ones.
    #[test]
    fn replacing_the_rules_takes_effect_before_the_ttl_expires() {
        let mut cached =
            CachedRuleSet::new(admin_rules(), MemoryStore::new(Duration::from_secs(3600)));
        let request = RequestFacts {
            path: "/admin/keys".to_owned(),
            subject: Some("u".to_owned()),
            roles: vec!["admin".to_owned()],
            ..facts()
        };

        assert_eq!(
            cached.decide(&request, at(0)).decision.action,
            Action::Allow
        );
        assert!(cached.decide(&request, at(1)).cached);

        // Revoke, with the old entry still well inside its hour-long TTL.
        cached.replace_rules(RuleSet::new(vec![deny(
            "no-admin",
            vec![Criterion::PathPrefix("/admin".to_owned())],
        )]));

        let after = cached.decide(&request, at(2));
        assert_eq!(
            after.decision.action,
            Action::Deny,
            "a revocation must not wait out the TTL"
        );
        assert!(
            !after.cached,
            "and it must be recomputed, not served from the old generation"
        );
    }

    /// A RULE CHANGE ALSO RE-DERIVES WHAT THE KEY COVERS.
    ///
    /// New rules can read facts the old ones did not. If `dependencies` were computed once at
    /// construction, the key would keep omitting a fact the new rules consult, and callers
    /// the new rules distinguish would share an entry.
    #[test]
    fn replacing_the_rules_re_derives_the_key_fields() {
        let mut cached = CachedRuleSet::new(
            RuleSet::new(vec![allow(
                "any-path",
                vec![Criterion::PathPrefix("/x".to_owned())],
            )]),
            MemoryStore::new(Duration::from_secs(60)),
        );
        assert!(
            !cached.dependencies().reads(FactField::Roles),
            "the first rule set ignores roles"
        );

        cached.replace_rules(admin_rules());
        assert!(
            cached.dependencies().reads(FactField::Roles),
            "the new rule set reads roles, so the key must now carry them"
        );

        let admin = RequestFacts {
            path: "/admin/k".to_owned(),
            subject: Some("u".to_owned()),
            roles: vec!["admin".to_owned()],
            ..facts()
        };
        let guest = RequestFacts {
            roles: vec!["guest".to_owned()],
            ..admin.clone()
        };
        assert_ne!(cached.key_for(&admin), cached.key_for(&guest));
    }

    /// A CACHE OUTAGE FALLS BACK TO FULL EVALUATION.
    ///
    /// A cache is an optimisation, and an optimisation that can refuse a request is a
    /// liability. The answer is always computable from the rules and the facts.
    #[test]
    fn a_cache_outage_still_answers_and_answers_correctly() {
        let store = FlakyStore::new(Duration::from_secs(60));
        let cached = CachedRuleSet::new(admin_rules(), store);
        let admin = RequestFacts {
            path: "/admin/keys".to_owned(),
            subject: Some("u".to_owned()),
            roles: vec!["admin".to_owned()],
            ..facts()
        };
        let guest = RequestFacts {
            roles: vec!["guest".to_owned()],
            ..admin.clone()
        };

        assert_eq!(cached.decide(&admin, at(0)).decision.action, Action::Allow);

        // The cache goes away. The rules are untouched; the store is what fails.
        cached.store().set_up(false);

        let during = cached.decide(&admin, at(1));
        assert_eq!(during.decision.action, Action::Allow, "still answered");
        assert!(!during.cached, "computed, not served");
        assert!(
            !during.store_available,
            "and the outage is reported, not hidden"
        );

        // And it is still CORRECT during the outage, not just non-failing.
        let guest_during = cached.decide(&guest, at(1));
        assert_eq!(
            guest_during.decision.action,
            Action::Deny,
            "an outage must not turn into an admission"
        );

        // A DOWN CACHE IS NOT WRITTEN TO. Hammering a dead cache with stores on every
        // request is how a cache outage becomes a latency incident, so the outage path
        // skips the write entirely rather than attempting one and swallowing the error.
        let before = cached.store().puts();
        let _ = cached.decide(&admin, at(1));
        assert_eq!(
            cached.store().puts(),
            before,
            "an unavailable cache must not be written to on every request"
        );

        // Recovery needs no intervention.
        cached.store().set_up(true);
        let recovered = cached.decide(&admin, at(2));
        assert!(recovered.store_available);
        assert!(
            recovered.cached,
            "the entry stored before the outage is still live and still served"
        );

        // And a key that was never stored gets stored now. Checking this with `admin`
        // would prove nothing: its entry predates the outage and is still inside the TTL,
        // so that request is a HIT and a hit writes nothing.
        let fresh = RequestFacts {
            subject: Some("someone-else".to_owned()),
            ..admin.clone()
        };
        let before_fresh = cached.store().puts();
        assert!(!cached.decide(&fresh, at(2)).cached);
        assert!(
            cached.store().puts() > before_fresh,
            "once the cache is back, a miss stores again"
        );
    }

    /// AN OUTAGE IS REPORTED AS AN OUTAGE, not as a miss.
    ///
    /// Both lead to evaluation, but they are different operational events, and a metric that
    /// cannot tell them apart cannot show an operator their cache is down.
    #[test]
    fn an_outage_is_distinguishable_from_a_miss() {
        let cached = CachedRuleSet::new(admin_rules(), FlakyStore::new(Duration::from_secs(60)));
        let request = RequestFacts {
            path: "/admin/keys".to_owned(),
            subject: Some("u".to_owned()),
            roles: vec!["admin".to_owned()],
            ..facts()
        };

        let miss = cached.decide(&request, at(0));
        assert!(
            !miss.cached && miss.store_available,
            "a miss: cache up, no entry"
        );

        cached.store().set_up(false);
        let outage = cached.decide(&request, at(1));
        assert!(
            !outage.cached && !outage.store_available,
            "an outage: distinguishable from the miss above"
        );
    }

    /// A RULE SET READING NOTHING COLLAPSES TO ONE ENTRY.
    #[test]
    fn rules_that_read_nothing_share_a_single_entry() {
        let set = RuleSet::new(vec![allow("everything", vec![])]);
        let cached = CachedRuleSet::new(set, MemoryStore::new(Duration::from_secs(60)));
        assert!(cached.dependencies().reads_nothing());

        let one = RequestFacts {
            path: "/a".to_owned(),
            ..facts()
        };
        let two = RequestFacts {
            path: "/b".to_owned(),
            subject: Some("anyone".to_owned()),
            ..facts()
        };
        assert_eq!(cached.key_for(&one), cached.key_for(&two));
        assert!(!cached.decide(&one, at(0)).cached);
        assert!(cached.decide(&two, at(0)).cached);
        assert_eq!(cached.rules().rules().len(), 1);
    }

    /// A CACHED ANSWER IS THE SAME ANSWER, across the whole corpus.
    #[test]
    fn caching_never_changes_the_answer() {
        let plain = corpus_rules();
        let cached = CachedRuleSet::new(corpus_rules(), MemoryStore::new(Duration::from_secs(60)));
        for case in corpus_cases() {
            let expected = plain.decide(&case.facts);
            // Twice: the miss that fills, and the hit that serves.
            let first = cached.decide(&case.facts, at(0));
            let second = cached.decide(&case.facts, at(1));
            assert_eq!(first.decision, expected, "{}: miss", case.name);
            assert_eq!(second.decision, expected, "{}: hit", case.name);
        }
    }

    /// THE GENERATION IS WHAT INVALIDATES, pinned with the dependencies held CONSTANT.
    ///
    /// `replacing_the_rules_takes_effect_before_the_ttl_expires` swaps an admin rule for a
    /// blanket deny, and those two rule sets read DIFFERENT facts: the key changes because
    /// `dependencies` changed, not because the generation did. A sweep proved it, twice:
    /// removing the generation from the key and removing the bump from `replace_rules` both
    /// left the whole suite green.
    ///
    /// So this swaps rules that read EXACTLY the same facts (one path prefix, nothing else)
    /// and differ only in their answer. Nothing but the generation can make the old entry
    /// unreachable here.
    #[test]
    fn the_generation_alone_invalidates_when_the_key_fields_are_unchanged() {
        let before = RuleSet::new(vec![allow(
            "gate",
            vec![Criterion::PathPrefix("/x".to_owned())],
        )]);
        let after = RuleSet::new(vec![deny(
            "gate",
            vec![Criterion::PathPrefix("/x".to_owned())],
        )]);
        assert_eq!(
            before.dependencies(),
            after.dependencies(),
            "precondition: the two rule sets read the same facts, so only the generation differs"
        );

        let mut cached = CachedRuleSet::new(before, MemoryStore::new(Duration::from_secs(3600)));
        let request = RequestFacts {
            path: "/x/y".to_owned(),
            ..facts()
        };

        assert_eq!(
            cached.decide(&request, at(0)).decision.action,
            Action::Allow
        );
        assert!(
            cached.decide(&request, at(1)).cached,
            "precondition: it is cached"
        );

        let old_key = cached.key_for(&request);
        cached.replace_rules(after);
        let new_key = cached.key_for(&request);
        assert_ne!(
            old_key, new_key,
            "the same request must present a different key after a rule change"
        );

        let served = cached.decide(&request, at(2));
        assert_eq!(
            served.decision.action,
            Action::Deny,
            "the old admission is unreachable, with an hour of TTL left on it"
        );
        assert!(!served.cached);
    }

    /// THE COLLISION THAT SERVED AN ALLOW TO A DENIED CALLER.
    ///
    /// `matches` decides with `.any()` over every header entry whose name matches
    /// case-insensitively; the key was built with `.find()`, which picks one arbitrarily
    /// from a `HashMap`. A request carrying two spellings was evaluated against both and
    /// stored under a key belonging to a different equivalence class, so an ordinary later
    /// request with one correctly-spelled header was served that stored admission.
    #[test]
    fn two_spellings_of_one_header_cannot_poison_another_callers_entry() {
        let set = RuleSet::new(vec![allow(
            "billing",
            vec![Criterion::Header {
                name: "X-Service".to_owned(),
                value: "billing".to_owned(),
            }],
        )]);
        let plain = RuleSet::new(set.rules().to_vec());
        let cached = CachedRuleSet::new(set, MemoryStore::new(Duration::from_secs(60)));

        // Carries BOTH spellings. The engine allows it, because one of them matches.
        let mut poisoner = facts();
        poisoner
            .headers
            .insert("X-Service".to_owned(), "public".to_owned());
        poisoner
            .headers
            .insert("x-service".to_owned(), "billing".to_owned());

        // Carries only the non-matching spelling. The engine denies it.
        let mut victim = facts();
        victim
            .headers
            .insert("X-Service".to_owned(), "public".to_owned());

        assert_eq!(
            plain.decide(&poisoner).action,
            Action::Allow,
            "precondition"
        );
        assert_eq!(plain.decide(&victim).action, Action::Deny, "precondition");

        assert_ne!(
            cached.key_for(&poisoner),
            cached.key_for(&victim),
            "requests the rules answer differently must not share a key"
        );

        let _ = cached.decide(&poisoner, at(0));
        let served = cached.decide(&victim, at(0));
        assert_eq!(
            served.decision.action,
            Action::Deny,
            "the victim must get its own answer, not the admission stored by the poisoner"
        );
    }

    /// THE KEY IS A FUNCTION OF ITS INPUT.
    ///
    /// `HashMap` iteration order varies per construction, so a key built by picking one
    /// arbitrary matching entry was not stable: a review got two different keys from 200
    /// constructions of one identical request.
    #[test]
    fn one_request_always_produces_one_key() {
        let set = RuleSet::new(vec![allow(
            "billing",
            vec![Criterion::Header {
                name: "X-Service".to_owned(),
                value: "billing".to_owned(),
            }],
        )]);
        let cached = CachedRuleSet::new(set, MemoryStore::new(Duration::from_secs(60)));

        let build = || {
            let mut request = facts();
            request
                .headers
                .insert("X-Service".to_owned(), "public".to_owned());
            request
                .headers
                .insert("x-service".to_owned(), "billing".to_owned());
            cached.key_for(&request)
        };
        let first = build();
        for _ in 0..100 {
            assert_eq!(
                build(),
                first,
                "the key must not depend on map iteration order"
            );
        }
    }

    /// THE KEY NORMALIZES EXACTLY WHERE THE ENGINE DOES.
    ///
    /// Method and host compare case-insensitively, and an empty subject reads as anonymous.
    /// A key that disagrees splits the cache for callers the rules cannot tell apart: the
    /// harmless direction, but it makes the feature pointless and it is a second reading of
    /// the same field.
    #[test]
    fn the_key_normalizes_the_same_way_the_engine_compares() {
        let set = RuleSet::new(vec![allow(
            "mixed",
            vec![
                Criterion::Method(vec!["GET".to_owned()]),
                Criterion::Host("app.example.com".to_owned()),
                Criterion::Subject(SubjectCheck::Anonymous),
            ],
        )]);
        let cached = CachedRuleSet::new(set, MemoryStore::new(Duration::from_secs(60)));

        let lower = RequestFacts {
            method: "get".to_owned(),
            host: "app.example.com".to_owned(),
            subject: None,
            ..facts()
        };
        let upper = RequestFacts {
            method: "GET".to_owned(),
            host: "APP.Example.COM".to_owned(),
            // An empty subject is anonymous to the engine, so it must be one caller here.
            subject: Some(String::new()),
            ..lower.clone()
        };

        assert_eq!(
            cached.key_for(&lower),
            cached.key_for(&upper),
            "callers the engine cannot tell apart must share an entry"
        );
        assert!(!cached.decide(&lower, at(0)).cached);
        assert!(cached.decide(&upper, at(0)).cached);
    }

    /// AN ENTRY STAMPED IN THE FUTURE IS NOT FRESH FOREVER.
    ///
    /// `saturating_duration_since` returns zero when the entry is newer than `now`, i.e. age
    /// zero, i.e. fresh. The comment beside it claimed the opposite for the whole of this
    /// PR's first version, and a review measured six hits out of six across a simulated year
    /// on a thirty-second TTL.
    #[test]
    fn an_entry_stamped_in_the_future_is_not_served() {
        let request = RequestFacts {
            path: "/admin/keys".to_owned(),
            subject: Some("u".to_owned()),
            roles: vec!["admin".to_owned()],
            ..facts()
        };

        // A FRESH store per probe. Reusing one would prove nothing after the first read:
        // the miss refills at the reading instant, so the entry is no longer future-stamped
        // and every later read is a legitimate hit. An earlier version of this test reused
        // one store and failed on its second probe for exactly that reason.
        for earlier in [0, 1, 60, 3_600, 86_400] {
            let cached =
                CachedRuleSet::new(admin_rules(), MemoryStore::new(Duration::from_secs(30)));
            assert!(
                !cached.decide(&request, at(1_000_000)).cached,
                "precondition: the fill is a miss"
            );
            assert!(
                !cached.decide(&request, at(earlier)).cached,
                "a future-stamped entry must not be served at t={earlier}"
            );
        }
    }

    /// THE STORE IS BOUNDED, and expired entries are what it drops first.
    ///
    /// The path is in the key whenever a rule reads it, and on a forward-auth surface the
    /// path is unauthenticated attacker input, so unbounded growth is driven by exactly the
    /// traffic this sits in front of.
    #[test]
    fn the_store_does_not_grow_without_bound() {
        let store = MemoryStore::new(Duration::from_secs(1)).with_max_entries(64);
        let cached = CachedRuleSet::new(
            RuleSet::new(vec![allow(
                "any",
                vec![Criterion::PathPrefix("/p".to_owned())],
            )]),
            store,
        );

        for n in 0..5_000_u32 {
            let request = RequestFacts {
                path: format!("/p/{n}"),
                ..facts()
            };
            // Each request well past the previous entry's TTL, so the expired-entry pass is
            // the one doing the work.
            let _ = cached.decide(&request, at(u64::from(n) * 10));
        }
        let retained = cached.store().len();
        assert!(
            retained <= 64,
            "the store must stay at or under its ceiling, retained {retained}"
        );
        assert!(
            !cached.store().is_empty(),
            "and it must still be caching something"
        );
    }

    /// A SECOND REPLICA OVER A SHARED STORE CANNOT SERVE REVOKED RULES.
    ///
    /// The generation was a per-instance counter starting at zero, so two processes over one
    /// store both started at zero and the second read the first's entries. A review built
    /// exactly this and watched a replica holding DENY rules serve a cached ALLOW. The
    /// fingerprint has no per-instance history, so the same rules agree everywhere and
    /// different rules never collide.
    #[test]
    fn a_replica_with_revoked_rules_does_not_read_the_old_ones_entries() {
        struct Shared<'a>(&'a MemoryStore);
        impl DecisionStore for Shared<'_> {
            fn get(&self, key: &DecisionKey, now: Instant) -> CacheOutcome {
                self.0.get(key, now)
            }
            fn put(&self, key: DecisionKey, decision: Decision, now: Instant) {
                self.0.put(key, decision, now);
            }
        }

        let shared = MemoryStore::new(Duration::from_secs(3600));
        let permissive = RuleSet::new(vec![allow(
            "gate",
            vec![Criterion::PathPrefix("/x".to_owned())],
        )]);
        let revoked = RuleSet::new(vec![deny(
            "gate",
            vec![Criterion::PathPrefix("/x".to_owned())],
        )]);
        assert_eq!(
            permissive.dependencies(),
            revoked.dependencies(),
            "precondition: the two read the same facts, so only the generation can differ"
        );

        let request = RequestFacts {
            path: "/x/y".to_owned(),
            ..facts()
        };

        let replica_a = CachedRuleSet::new(permissive, Shared(&shared));
        assert_eq!(
            replica_a.decide(&request, at(0)).decision.action,
            Action::Allow
        );

        // A fresh process that has only ever held the revoked rules.
        let replica_b = CachedRuleSet::new(revoked, Shared(&shared));
        let served = replica_b.decide(&request, at(1));
        assert_eq!(
            served.decision.action,
            Action::Deny,
            "a replica must never serve an answer computed under rules it does not hold"
        );
        assert!(!served.cached);
    }

    /// THE FINGERPRINT DISTINGUISHES EVERY PART OF A RULE A DECISION CAN DEPEND ON.
    #[test]
    fn the_fingerprint_changes_with_anything_that_changes_a_decision() {
        let base = RuleSet::new(vec![allow(
            "r",
            vec![Criterion::Header {
                name: "X-A".to_owned(),
                value: "one".to_owned(),
            }],
        )]);
        let variants = vec![
            (
                "the action",
                RuleSet::new(vec![deny(
                    "r",
                    vec![Criterion::Header {
                        name: "X-A".to_owned(),
                        value: "one".to_owned(),
                    }],
                )]),
            ),
            (
                // `describe` omits a header's configured value, so the fingerprint hashes it
                // separately. Without that, two rules requiring different values collide.
                "the required header value",
                RuleSet::new(vec![allow(
                    "r",
                    vec![Criterion::Header {
                        name: "X-A".to_owned(),
                        value: "two".to_owned(),
                    }],
                )]),
            ),
            (
                "the header name",
                RuleSet::new(vec![allow(
                    "r",
                    vec![Criterion::Header {
                        name: "X-B".to_owned(),
                        value: "one".to_owned(),
                    }],
                )]),
            ),
            (
                "the rule name",
                RuleSet::new(vec![allow(
                    "other",
                    vec![Criterion::Header {
                        name: "X-A".to_owned(),
                        value: "one".to_owned(),
                    }],
                )]),
            ),
            ("an added rule", {
                let mut rules = base.rules().to_vec();
                rules.push(deny("extra", vec![]));
                RuleSet::new(rules)
            }),
            ("no rules at all", RuleSet::default()),
        ];
        for (what, other) in variants {
            assert_ne!(
                base.fingerprint(),
                other.fingerprint(),
                "changing {what} must change the fingerprint"
            );
        }

        // And it is stable: the same rules built twice agree, which is what makes a shared
        // cache usable at all.
        let rebuilt = RuleSet::new(base.rules().to_vec());
        assert_eq!(base.fingerprint(), rebuilt.fingerprint());
    }

    /// ROLE ORDER DOES NOT SPLIT THE CACHE EITHER.
    ///
    /// `membership_order_does_not_split_the_cache` covered groups only, and the roles sort
    /// was unpinned: its mutant survived.
    #[test]
    fn role_order_does_not_split_the_cache() {
        let set = RuleSet::new(vec![allow(
            "ops",
            vec![Criterion::Subject(SubjectCheck::HasRole("ops".to_owned()))],
        )]);
        let cached = CachedRuleSet::new(set, MemoryStore::new(Duration::from_secs(60)));
        let one = RequestFacts {
            subject: Some("u".to_owned()),
            roles: vec!["ops".to_owned(), "audit".to_owned()],
            ..facts()
        };
        let two = RequestFacts {
            roles: vec!["audit".to_owned(), "ops".to_owned()],
            ..one.clone()
        };
        assert_eq!(cached.key_for(&one), cached.key_for(&two));
        assert!(!cached.decide(&one, at(0)).cached);
        assert!(cached.decide(&two, at(0)).cached);
    }

    /// RECLAMATION DROPS THE EXPIRED AND KEEPS THE LIVE.
    ///
    /// The size bound alone cannot tell the two passes apart: with the expired-entry pass
    /// disabled, the fallback still clears and the map still stays small, so
    /// `the_store_does_not_grow_without_bound` passes either way. A sweep showed that.
    ///
    /// What distinguishes them is what SURVIVES. Dropping an expired entry is free, because
    /// it was already ignored on read. Clearing takes live entries with it, which is a
    /// correctness-neutral but pointless loss of exactly the entries the cache exists for.
    #[test]
    fn reclamation_keeps_a_live_entry_and_drops_the_expired_ones() {
        let store = MemoryStore::new(Duration::from_secs(1_000)).with_max_entries(16);
        let cached = CachedRuleSet::new(
            RuleSet::new(vec![allow(
                "any",
                vec![Criterion::PathPrefix("/p".to_owned())],
            )]),
            store,
        );
        let path = |n: u32| RequestFacts {
            path: format!("/p/{n}"),
            ..facts()
        };

        // Fifteen entries that will be long expired by the time reclamation runs.
        for n in 0..15_u32 {
            let _ = cached.decide(&path(n), at(0));
        }

        // The one that must survive: stored well after the others, and still live.
        let live = path(999);
        assert!(!cached.decide(&live, at(5_000)).cached, "fills at 5000");

        // One more insert at the same instant. That is enough to reach the ceiling, so
        // reclamation runs with the fifteen above expired and the live entry not.
        let _ = cached.decide(&path(100), at(5_000));

        assert!(
            cached.decide(&live, at(5_001)).cached,
            "an entry still inside its TTL must survive a reclamation driven by expired ones"
        );
    }

    // ----------------------------------------------------------------------------------
    // The reached authentication context (issue #154 criterion 4).
    // ----------------------------------------------------------------------------------

    /// The canonical rungs, so a test asserts against what a SESSION actually carries rather
    /// than against a short alias no achieved context is ever spelled with.
    fn pwd() -> String {
        crate::step_up::canonical_step_up_acr("pwd")
    }

    fn mfa() -> String {
        crate::step_up::canonical_step_up_acr("mfa")
    }

    fn payments_need_mfa() -> RuleSet {
        RuleSet::new(vec![rule(
            "payments-need-mfa",
            vec![Criterion::PathPrefix("/payments".to_owned())],
            Action::StepUp { acr: mfa() },
        )])
    }

    fn at_payments(acr: Option<&str>) -> RequestFacts {
        RequestFacts {
            path: "/payments/transfer".to_owned(),
            subject: Some("alice".to_owned()),
            acr: acr.map(str::to_owned),
            ..facts()
        }
    }

    /// THE DEFECT THIS CRITERION EXISTED AROUND: a step-up rule that never terminates.
    ///
    /// The engine shipped with `Action::StepUp` and with no fact describing the
    /// authentication a request arrived with. A caller was challenged, authenticated,
    /// returned, matched the same rule, and was challenged again -- forever -- because
    /// nothing in a rule set could observe that the challenge had been met.
    ///
    /// Both halves are asserted in ONE test on purpose. Either alone is satisfiable by a
    /// broken engine: a rule that always challenges passes the first, and a rule that always
    /// admits passes the second.
    #[test]
    fn a_step_up_challenges_a_weak_session_and_admits_the_same_caller_once_it_steps_up() {
        let rules = payments_need_mfa();

        assert_eq!(
            rules.decide(&at_payments(Some(&pwd()))).action,
            Action::StepUp { acr: mfa() },
            "a password session has not reached the rung the rule names"
        );

        let admitted = rules.decide(&at_payments(Some(&mfa())));
        assert_eq!(
            admitted.action,
            Action::Allow,
            "the same rule must ADMIT the caller who answered its challenge, or the caller \
             is redirected to authenticate for as long as they keep returning"
        );
        assert_eq!(
            admitted.matched.as_deref(),
            Some("payments-need-mfa"),
            "the admission is attributed to the rule that required it, so an operator \
             reading a trace can see which requirement was met"
        );
    }

    /// AN ANONYMOUS CALLER IS CHALLENGED, NOT ADMITTED.
    ///
    /// `None` is the value a surface that has not wired the achieved context produces, and
    /// the value every `RequestFacts` literal in this repository carried before the field
    /// existed. It must never satisfy a floor.
    #[test]
    fn no_reached_context_satisfies_no_step_up_and_no_floor() {
        assert_eq!(
            payments_need_mfa().decide(&at_payments(None)).action,
            Action::StepUp { acr: mfa() }
        );

        let floored = RuleSet::new(vec![allow(
            "strong-only",
            vec![Criterion::AcrAtLeast(pwd())],
        )]);
        assert_eq!(
            floored.decide(&at_payments(None)).action,
            Action::Deny,
            "a rule whose floor is unmet does not match, and nothing below it admits"
        );
        assert_eq!(
            floored.decide(&at_payments(Some(""))).action,
            Action::Deny,
            "an EMPTY acr is not a reached context, for the reason an empty subject is not a \
             subject: it is what a partially filled fact set produces"
        );
    }

    /// THE DEGENERATE PAIR: an empty floor met by an empty reached context.
    ///
    /// The assertion above passes with or without `achieved_acr`'s emptiness filter, because a
    /// blank context fails a REAL floor either way -- a mutation proved it vacuous. The filter
    /// only bites when BOTH sides are blank, and then it decides the whole question: an empty
    /// string equals an empty string, so `acr_satisfies` returns true on its first line and a
    /// rule requiring an authentication level nobody named is satisfied by a request that
    /// named none either.
    ///
    /// Configuration cannot reach this: an empty `acr_at_least` is refused as invalid and an
    /// empty step-up `acr` names no rung. The engine is a public API with public fields, so
    /// this is pinned where the decision is made rather than where one caller happens to
    /// validate.
    #[test]
    fn an_empty_floor_is_not_satisfied_by_an_empty_reached_context() {
        let blank_floor = RuleSet::new(vec![allow(
            "floor-nobody-wrote",
            vec![Criterion::AcrAtLeast(String::new())],
        )]);
        assert_eq!(
            blank_floor.decide(&at_payments(Some(""))).action,
            Action::Deny,
            "two blanks matching is a rule that enforces nothing while reading as a \
             restriction"
        );
        assert_eq!(
            blank_floor.decide(&at_payments(Some(&mfa()))).action,
            Action::Deny,
            "and no real authentication reaches an unnamed floor either"
        );

        let blank_step_up = RuleSet::new(vec![rule(
            "step-up-to-nowhere",
            vec![Criterion::PathPrefix("/payments".to_owned())],
            Action::StepUp { acr: String::new() },
        )]);
        assert_eq!(
            blank_step_up.decide(&at_payments(Some(""))).action,
            Action::StepUp { acr: String::new() },
            "a step-up naming no rung must not be answered by a caller who reached no rung"
        );
    }

    /// THE LADDER, NOT STRING EQUALITY. An `mfa` session satisfies a `pwd` floor.
    ///
    /// Equality would be the quiet failure: every rule would still enforce SOMETHING, and a
    /// deployment would only discover that its strongest sessions were being challenged for
    /// its weakest requirement when a user complained.
    #[test]
    fn a_stronger_rung_satisfies_a_weaker_floor_in_both_the_action_and_the_criterion() {
        let step_up_to_pwd = RuleSet::new(vec![rule(
            "any-authentication",
            vec![Criterion::PathPrefix("/payments".to_owned())],
            Action::StepUp { acr: pwd() },
        )]);
        assert_eq!(
            step_up_to_pwd.decide(&at_payments(Some(&mfa()))).action,
            Action::Allow,
            "an mfa session has reached more than a pwd floor asks for"
        );

        let floor_pwd = RuleSet::new(vec![allow(
            "authenticated-at-all",
            vec![Criterion::AcrAtLeast(pwd())],
        )]);
        assert_eq!(
            floor_pwd.decide(&at_payments(Some(&mfa()))).action,
            Action::Allow
        );

        // ...and not the other way round.
        let floor_mfa = RuleSet::new(vec![allow(
            "strong-only",
            vec![Criterion::AcrAtLeast(mfa())],
        )]);
        assert_eq!(
            floor_mfa.decide(&at_payments(Some(&pwd()))).action,
            Action::Deny
        );
    }

    /// AN UNRANKED VALUE SATISFIES ONLY ITSELF, which is `acr_satisfies`'s contract and the
    /// reason a floor naming a value the deployment cannot issue is refused at conversion.
    #[test]
    fn an_unranked_reached_context_satisfies_only_an_exact_floor() {
        let invented = "urn:example:acr:invented";
        let exact = RuleSet::new(vec![allow(
            "exact",
            vec![Criterion::AcrAtLeast(invented.to_owned())],
        )]);
        assert_eq!(
            exact.decide(&at_payments(Some(invented))).action,
            Action::Allow
        );
        assert_eq!(
            exact.decide(&at_payments(Some(&mfa()))).action,
            Action::Deny,
            "a ranked rung cannot outrank a value that is on no ladder"
        );

        let ranked = RuleSet::new(vec![allow("ranked", vec![Criterion::AcrAtLeast(pwd())])]);
        assert_eq!(
            ranked.decide(&at_payments(Some(invented))).action,
            Action::Deny,
            "and an unranked session cannot satisfy a ranked floor"
        );
    }

    /// A STEP-UP ACTION MAKES THE REACHED CONTEXT A CACHE KEY INPUT, even though no criterion
    /// in the rule set mentions it.
    ///
    /// Dependencies were derived from CRITERIA alone, which was right while every action was
    /// a constant. A step-up rule is not a constant: it resolves to `Allow` for a caller who
    /// reached the ACR and challenges one who has not. Keying without the context means the
    /// first caller through the door leaves their `Allow` where the next caller finds it, so
    /// the step-up requirement is enforced for exactly one request per TTL.
    #[test]
    fn a_step_up_action_alone_puts_the_reached_context_in_the_cache_key() {
        let cached = CachedRuleSet::new(
            payments_need_mfa(),
            MemoryStore::new(Duration::from_secs(60)),
        );

        assert!(
            cached.dependencies().reads(FactField::Acr),
            "no criterion names the acr, and the ACTION still reads it"
        );

        let strong = at_payments(Some(&mfa()));
        let weak = at_payments(Some(&pwd()));
        assert_ne!(
            cached.key_for(&strong),
            cached.key_for(&weak),
            "two callers differing only in how strongly they authenticated must not share \
             one entry"
        );

        // The escalation, driven rather than argued: warm the entry with the caller who HAS
        // stepped up, then present the one who has not.
        assert_eq!(cached.decide(&strong, at(0)).decision.action, Action::Allow);
        let following = cached.decide(&weak, at(1));
        assert_eq!(
            following.decision.action,
            Action::StepUp { acr: mfa() },
            "the weaker caller must be challenged even though a stronger one was just admitted"
        );
        assert!(
            !following.cached,
            "and must not have been answered out of the stronger caller's entry"
        );
    }

    /// THE ORDER IS PART OF THE POLICY, so it is part of the generation a shared store keys on.
    ///
    /// Two replicas holding identical rules under different `oidc.acr_order` values resolve a
    /// step-up differently. Without the order in the fingerprint they share entries, and the
    /// laxer replica's admission answers the stricter replica's request.
    #[test]
    fn the_acr_order_participates_in_the_fingerprint_and_in_the_decision() {
        let default_ladder = payments_need_mfa();
        let inverted: Vec<String> = {
            let mut order = crate::step_up::default_acr_order();
            order.reverse();
            order
        };
        let reordered = payments_need_mfa().with_acr_order(inverted);

        assert_ne!(
            default_ladder.fingerprint(),
            reordered.fingerprint(),
            "the same rules under a different ladder are a different policy"
        );

        let weak = at_payments(Some(&pwd()));
        assert_eq!(
            default_ladder.decide(&weak).action,
            Action::StepUp { acr: mfa() }
        );
        assert_eq!(
            reordered.decide(&weak).action,
            Action::Allow,
            "under an inverted ladder pwd outranks mfa, which is what makes the two \
             fingerprints having to differ a correctness property rather than hygiene"
        );
    }

    /// `RuleSet::default()` MUST RANK, and this is why `Default` is written rather than derived.
    ///
    /// A derived `Default` gave an empty order. An empty order ranks nothing, so
    /// `acr_satisfies` falls back to exact equality and an `mfa` session stops satisfying a
    /// `pwd` floor: a rule set built the short way would have enforced a different policy from
    /// the identical one built through `new`.
    #[test]
    fn the_default_rule_set_carries_the_default_ladder() {
        assert_eq!(
            RuleSet::default().acr_order(),
            crate::step_up::default_acr_order(),
            "an empty order is not `no opinion`, it is `nothing outranks anything`"
        );

        let built = RuleSet {
            rules: vec![allow("floor", vec![Criterion::AcrAtLeast(pwd())])],
            ..RuleSet::default()
        };
        assert_eq!(
            built.decide(&at_payments(Some(&mfa()))).action,
            Action::Allow
        );
    }

    /// A SATISFIED STEP-UP IS REPORTED AS THE ADMISSION IT IS.
    ///
    /// `Explanation::why_denied` and `DryRun::would_allow` both branch on the action, and both
    /// would be wrong about this request if the resolution happened at the caller instead of
    /// inside the walk: a rehearsal would show a challenge for a caller enforcement admits.
    #[test]
    fn the_explanation_and_the_dry_run_agree_that_a_met_step_up_admitted() {
        let rules = payments_need_mfa();
        let met = at_payments(Some(&mfa()));

        let explained = rules.explain(&met);
        assert_eq!(explained.decision.action, Action::Allow);
        assert_eq!(explained.why_denied(), None);
        assert_eq!(explained.reason(), "allowed by rule payments-need-mfa");

        assert!(rules.dry_run(&met).would_allow());
        assert!(!rules.dry_run(&at_payments(Some(&pwd()))).would_allow());
    }

    /// `refusal` READS THE SAME RULES WITH THE OPPOSITE DEFAULT, and the fall-through is the
    /// whole point.
    ///
    /// Four rows, because three of them are satisfiable by a wrong implementation on their
    /// own: "an explicit deny refuses" passes against a function that refuses everything, and
    /// "an allow does not" passes against one that refuses nothing. The row that pins the
    /// behaviour is the fall-through, and it is the one an operator hits first -- a token
    /// request matches no path rule.
    #[test]
    fn only_an_explicit_deny_refuses_an_already_authorized_request() {
        let rules = RuleSet::new(vec![
            deny(
                "no-admin-area",
                vec![Criterion::PathPrefix("/admin".to_owned())],
            ),
            allow(
                "reports-for-alice",
                vec![
                    Criterion::PathPrefix("/reports".to_owned()),
                    Criterion::Subject(SubjectCheck::Is("alice".to_owned())),
                ],
            ),
            deny(
                "no-tokens-for-mallory",
                vec![Criterion::Subject(SubjectCheck::Is("mallory".to_owned()))],
            ),
            rule(
                "payments-need-mfa",
                vec![
                    Criterion::PathPrefix("/payments".to_owned()),
                    Criterion::Subject(SubjectCheck::Authenticated),
                ],
                Action::StepUp { acr: mfa() },
            ),
        ]);
        let at = |path: &str| RequestFacts {
            path: path.to_owned(),
            subject: Some("alice".to_owned()),
            ..facts()
        };

        // A PATH DENY DOES NOT REFUSE, even against a request whose path it matches. It says
        // nothing about who is asking, and this consumer's question is about the principal.
        // The resource reading of the same rule is asserted below to be unchanged.
        assert_eq!(rules.refusal(&at("/admin/users")), None);
        assert_eq!(
            rules.decide(&at("/admin/users")).matched.as_deref(),
            Some("no-admin-area"),
            "the premise: this rule DOES match, so the line above is a different reading \
             rather than a rule that simply never fires"
        );

        // A DENY THAT NAMES SOMEONE refuses, and names the rule so the log can.
        assert_eq!(
            rules
                .refusal(&RequestFacts {
                    subject: Some("mallory".to_owned()),
                    ..at("/anything")
                })
                .as_deref(),
            Some("no-tokens-for-mallory")
        );
        assert_eq!(rules.refusal(&at("/reports/q3")), None, "an allow does not");

        // THE FALL-THROUGH. `decide` answers this `(Deny, None)`, and reading the action alone
        // would refuse it -- which for a token issuance means one path rule stops every token.
        assert_eq!(
            rules.decide(&at("/somewhere-else")).action,
            Action::Deny,
            "the premise: this request IS denied as a resource request"
        );
        assert_eq!(
            rules.refusal(&at("/somewhere-else")),
            None,
            "and is NOT a refusal for a consumer whose request was already authorized"
        );

        // A STEP-UP IS NOT A REFUSAL HERE either: there is no caller to redirect at a mint.
        assert_eq!(
            rules.decide(&at("/payments/transfer")).action,
            Action::StepUp { acr: mfa() },
            "the premise: this rule does match and does demand a step-up"
        );
        assert_eq!(rules.refusal(&at("/payments/transfer")), None);
    }

    /// THE CATCH-ALL DENY EVERY FORWARD-AUTH LIST ENDS WITH MUST NOT STOP EVERY TOKEN.
    ///
    /// A review found this and it was a total outage on upgrade. `refusal` excused only the
    /// IMPLICIT fall-through; an operator writing the same default DOWN -- which is what this
    /// repository's own canonical rule list does, and what `validate_access_rule` steers them
    /// toward by refusing `path_prefix = "/"` -- produced `(Deny, Some("deny-the-rest"))` and
    /// refused every issuance in the deployment.
    ///
    /// Three rows, because the shape has three readings that must stay apart: the catch-all is
    /// inert here, a deny that NAMES someone still bites through it, and the resource reading
    /// of the identical set is unchanged.
    #[test]
    fn a_criteria_less_catch_all_deny_refuses_no_issuance() {
        let rules = RuleSet::new(vec![
            allow(
                "public-area",
                vec![Criterion::PathPrefix("/public".to_owned())],
            ),
            deny(
                "no-tokens-for-mallory",
                vec![Criterion::Subject(SubjectCheck::Is("mallory".to_owned()))],
            ),
            // How a catch-all is written: no criteria at all.
            deny("deny-the-rest", Vec::new()),
        ]);
        let issuance = |subject: &str| RequestFacts {
            subject: Some(subject.to_owned()),
            ..RequestFacts::default()
        };

        assert_eq!(
            rules.refusal(&issuance("alice")),
            None,
            "the terminal deny says nothing about who is asking, so it is not policy here"
        );
        assert_eq!(
            rules.refusal(&issuance("mallory")).as_deref(),
            Some("no-tokens-for-mallory"),
            "and a deny that DOES name someone must still bite, or the fix above turned the \
             whole consumer off"
        );

        // THE RESOURCE READING IS UNTOUCHED. The filter belongs to `refusal` alone: a
        // forward-auth request still falls to the catch-all, which is what it is for.
        let resource = RequestFacts {
            path: "/private".to_owned(),
            subject: Some("alice".to_owned()),
            ..facts()
        };
        assert_eq!(
            rules.decide(&resource).matched.as_deref(),
            Some("deny-the-rest")
        );
    }

    /// A REQUEST-SHAPED RULE CANNOT SHADOW A PRINCIPAL ONE, which is the admitting direction.
    ///
    /// `Criterion::Host` is exact equality and these facts carry an empty host, so a rule
    /// reading `host = ""` matched every issuance; a `path_matches` accepting the empty string
    /// does the same. First-match-wins then let such an `allow` sit above a `deny` an operator
    /// wrote and silently keep issuing. The doc claiming "an empty host equals no host" was
    /// simply wrong: an empty host equals an empty host.
    #[test]
    fn a_rule_matching_only_on_request_shape_neither_refuses_nor_shadows() {
        let rules = RuleSet::new(vec![
            allow(
                "empty-host-matches-everything",
                vec![Criterion::Host(String::new())],
            ),
            deny(
                "no-tokens-for-mallory",
                vec![Criterion::Subject(SubjectCheck::Is("mallory".to_owned()))],
            ),
        ]);
        let mallory = RequestFacts {
            subject: Some("mallory".to_owned()),
            ..RequestFacts::default()
        };

        // The premise: that allow really does match these facts.
        assert_eq!(
            rules.decide(&mallory).matched.as_deref(),
            Some("empty-host-matches-everything"),
            "an empty configured host equals the empty host an issuance carries"
        );
        assert_eq!(
            rules.refusal(&mallory).as_deref(),
            Some("no-tokens-for-mallory"),
            "and it must not shadow the deny below it"
        );

        // The same shape as a DENY refuses nothing either.
        let blanket = RuleSet::new(vec![deny(
            "empty-host-denies-everything",
            vec![Criterion::Host(String::new())],
        )]);
        assert_eq!(blanket.refusal(&mallory), None);
    }

    /// AN EMPTY RULE SET REFUSES NOTHING, which is the shipped default.
    ///
    /// Stated separately because it is the configuration every deployment starts from: if this
    /// were a refusal, installing the issuance consumer would stop every token in every
    /// deployment that never wrote a rule.
    #[test]
    fn a_rule_set_with_no_rules_refuses_nothing() {
        assert_eq!(RuleSet::default().refusal(&facts()), None);
        assert_eq!(
            RuleSet::default().decide(&facts()).action,
            Action::Deny,
            "while the resource reading of the same empty set still denies"
        );
    }

    /// THE THIRD CONSUMER'S ENTRY POINT, and the three readings of one rule set kept apart.
    ///
    /// The same set answers three different questions, and a row here for each, because the
    /// interesting property is that they DISAGREE on purpose: a forward-auth check resolves a
    /// met step-up into an admission, an issuance reads only explicit denials, and this returns
    /// the demand itself so the caller can merge it with four other floors.
    #[test]
    fn a_step_up_rule_yields_a_floor_here_and_a_verdict_at_the_other_two_consumers() {
        let rules = RuleSet::new(vec![rule(
            "finance-needs-mfa",
            vec![Criterion::Subject(SubjectCheck::InGroup(
                "finance".to_owned(),
            ))],
            Action::StepUp { acr: mfa() },
        )]);
        let in_finance = |acr: &str| RequestFacts {
            subject: Some("alice".to_owned()),
            groups: vec!["finance".to_owned()],
            acr: Some(acr.to_owned()),
            ..RequestFacts::default()
        };

        // THE FLOOR IS THE DEMAND, whether or not it is already met. That is the difference
        // from `decide`, and it is what lets the caller compose it with a `max_age` this
        // engine cannot express.
        assert_eq!(
            rules.step_up_floor(&in_finance(&pwd())).as_deref(),
            Some(mfa().as_str())
        );
        assert_eq!(
            rules.step_up_floor(&in_finance(&mfa())).as_deref(),
            Some(mfa().as_str()),
            "a session that already reached the rung still yields the floor: whether it is \
             SATISFIED is the step-up machinery's question, not this one's"
        );

        // ...while `decide` resolves the met one, which is what makes a forward-auth rule
        // terminate, and `refusal` reads neither as a denial.
        assert_eq!(rules.decide(&in_finance(&mfa())).action, Action::Allow);
        assert_eq!(
            rules.decide(&in_finance(&pwd())).action,
            Action::StepUp { acr: mfa() }
        );
        assert_eq!(rules.refusal(&in_finance(&pwd())), None);

        // Someone outside the group gets no floor at all.
        assert_eq!(
            rules.step_up_floor(&RequestFacts {
                subject: Some("bob".to_owned()),
                acr: Some(pwd()),
                ..RequestFacts::default()
            }),
            None
        );
    }

    /// FIRST MATCH WINS HERE TOO, and a request-shaped rule contributes nothing.
    ///
    /// Two ways this reading could quietly stop honouring the list. An `allow` above a step-up
    /// rule means the step-up rule was not reached, so scanning past it for a floor would make
    /// this the one reading where order does not hold. And a rule constraining only the request
    /// cannot select at an authorization endpoint, which names no resource path -- the same
    /// filter `refusal` applies, for the same reason.
    #[test]
    fn the_floor_respects_order_and_ignores_a_rule_that_names_no_principal() {
        let exempted = RuleSet::new(vec![
            allow(
                "alice-is-exempt",
                vec![Criterion::Subject(SubjectCheck::Is("alice".to_owned()))],
            ),
            rule(
                "everyone-needs-mfa",
                vec![Criterion::Subject(SubjectCheck::Authenticated)],
                Action::StepUp { acr: mfa() },
            ),
        ]);
        let at = |subject: &str| RequestFacts {
            subject: Some(subject.to_owned()),
            acr: Some(pwd()),
            ..RequestFacts::default()
        };
        assert_eq!(
            exempted.step_up_floor(&at("alice")),
            None,
            "the allow matched first, so the rule below it was never reached"
        );
        assert_eq!(
            exempted.step_up_floor(&at("bob")).as_deref(),
            Some(mfa().as_str()),
            "and it still applies to everyone the exemption did not name"
        );

        let request_shaped = RuleSet::new(vec![rule(
            "admin-area-needs-mfa",
            vec![Criterion::PathPrefix("/admin".to_owned())],
            Action::StepUp { acr: mfa() },
        )]);
        assert_eq!(
            request_shaped.step_up_floor(&at("alice")),
            None,
            "an authorization request has no resource path for this to constrain"
        );

        // THE TWO SHAPES THAT WOULD MATCH ANYWAY, which is where the filter actually bites.
        //
        // A mutation proved the row above vacuous: `PathPrefix` fails against an empty path
        // whether or not the filter runs, so deleting the filter left it green. These do not
        // fail on their own -- an empty configured host EQUALS the empty host these facts
        // carry, and a rule with no criteria matches everything -- so without the filter each
        // would demand an ACR of every authorization request in the deployment.
        for (name, criteria) in [
            (
                "empty-host-matches-everything",
                vec![Criterion::Host(String::new())],
            ),
            ("catch-all", Vec::new()),
        ] {
            let blanket = RuleSet::new(vec![rule(
                name,
                criteria.clone(),
                Action::StepUp { acr: mfa() },
            )]);
            // The premise: it really does match, so the line below is the filter and not a
            // criterion that happened to fail.
            assert_eq!(
                blanket.decide(&at("alice")).matched.as_deref(),
                Some(name),
                "{name} must match these facts for this row to measure anything"
            );
            assert_eq!(
                blanket.step_up_floor(&at("alice")),
                None,
                "{name} says nothing about who is asking, so it names no floor here"
            );
        }

        // ...and an operator who DOES mean "everybody" says so, which every issuance satisfies.
        let everybody = RuleSet::new(vec![rule(
            "everybody-needs-mfa",
            vec![Criterion::Subject(SubjectCheck::Authenticated)],
            Action::StepUp { acr: mfa() },
        )]);
        assert_eq!(
            everybody.step_up_floor(&at("alice")).as_deref(),
            Some(mfa().as_str())
        );
    }
}
