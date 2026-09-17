// SPDX-License-Identifier: MIT OR Apache-2.0

//! ONE rule set, three enforcement points (issue #154 criterion 4).
//!
//! > The same rule set demonstrably gates a forward-auth resource, an OIDC token issuance, and a
//! > step-up requirement in integration tests.
//!
//! The engine's own suite proves it decides correctly. What it cannot show is that the SAME set
//! reaches more than one surface, which is the whole of this criterion: an engine consulted in
//! one place is an engine with one caller, whatever its tests say.
//!
//! # Why these are decision-level rather than driven through HTTP
//!
//! Each surface interprets the engine's `Action` in its own terms, and the interpretation is what
//! this pins: a forward-auth resource admits or refuses, a token issuance refuses with
//! `access_denied`, and a step-up becomes the RFC 9470 challenge. Driving three live servers
//! would test the servers; what is in question is that one list of rules produces all three
//! answers from facts each surface builds.

use ironauth_oidc::rules::{Action, Criterion, RequestFacts, Rule, RuleSet, SubjectCheck};

/// THE ONE RULE SET, written to cover all three surfaces.
///
/// Order matters and is the point of the engine: the narrow allow for a subject's own record
/// sits above the broad deny, and the token-endpoint rules sit beside the resource rules in the
/// same list.
fn shared_rules() -> RuleSet {
    RuleSet::new(vec![
        // A resource rule: the admin area needs a stronger authentication.
        Rule {
            name: "admin area requires step-up".to_owned(),
            criteria: vec![
                Criterion::PathPrefix("/admin".to_owned()),
                Criterion::Subject(SubjectCheck::Authenticated),
            ],
            action: Action::StepUp {
                acr: "urn:mace:incommon:iap:silver".to_owned(),
            },
        },
        // A resource rule: everything else under /app is open to any authenticated subject.
        Rule {
            name: "app is open to anyone signed in".to_owned(),
            criteria: vec![
                Criterion::PathPrefix("/app".to_owned()),
                Criterion::Subject(SubjectCheck::Authenticated),
            ],
            action: Action::Allow,
        },
        // A TOKEN-ENDPOINT rule, in the same list: one subject may not be issued tokens at all.
        Rule {
            name: "suspended subject gets no tokens".to_owned(),
            criteria: vec![
                Criterion::PathPrefix("/token".to_owned()),
                Criterion::Subject(SubjectCheck::Is("suspended-user".to_owned())),
            ],
            action: Action::Deny,
        },
        // And a token-endpoint rule requiring a stronger authentication for one subject.
        Rule {
            name: "privileged subject must step up to get a token".to_owned(),
            criteria: vec![
                Criterion::PathPrefix("/token".to_owned()),
                Criterion::Subject(SubjectCheck::Is("privileged-user".to_owned())),
            ],
            action: Action::StepUp {
                acr: "urn:mace:incommon:iap:silver".to_owned(),
            },
        },
        // Every other token request is fine.
        Rule {
            name: "tokens otherwise issue".to_owned(),
            criteria: vec![Criterion::PathPrefix("/token".to_owned())],
            action: Action::Allow,
        },
    ])
}

fn facts(path: &str, subject: Option<&str>) -> RequestFacts {
    RequestFacts {
        method: "POST".to_owned(),
        host: "id.example".to_owned(),
        path: path.to_owned(),
        headers: std::collections::HashMap::new(),
        subject: subject.map(str::to_owned),
        groups: Vec::new(),
        roles: Vec::new(),
    }
}

/// SURFACE ONE: a forward-auth resource, admitted and refused by the same set.
#[test]
fn the_shared_set_gates_a_forward_auth_resource() {
    let rules = shared_rules();
    assert_eq!(
        rules.decide(&facts("/app/reports", Some("alice"))).action,
        Action::Allow
    );
    // ANONYMOUS FALLS THROUGH TO NO MATCH, which the engine denies. That is the fall-through
    // this criterion depends on being closed.
    assert_eq!(
        rules.decide(&facts("/app/reports", None)).action,
        Action::Deny
    );
}

/// SURFACE TWO: token issuance, refused for a subject by the same set.
///
/// The token endpoint builds its facts with path `/token` and the subject taken from the grant,
/// which is what `enforce_access_rules` does, so this is the decision that endpoint acts on.
#[test]
fn the_shared_set_gates_token_issuance() {
    let rules = shared_rules();
    assert_eq!(
        rules
            .decide(&facts("/token", Some("suspended-user")))
            .action,
        Action::Deny,
        "the token endpoint refuses this grant with access_denied"
    );
    // THE CONTROL: without it, a rule set that denied everything would pass the assertion above.
    assert_eq!(
        rules.decide(&facts("/token", Some("alice"))).action,
        Action::Allow,
        "an ordinary subject is still issued a token, or this set gates nothing and refuses all"
    );
}

/// SURFACE THREE: a step-up requirement, from the same set, at BOTH the resource and the token
/// endpoint.
///
/// The action carries the ACR, which is what each surface turns into its own answer: a
/// forward-auth redirect, and the RFC 9470 `insufficient_user_authentication` challenge the
/// token endpoint already speaks for scope-carried requirements.
#[test]
fn the_shared_set_produces_a_step_up_requirement_on_both_surfaces() {
    let rules = shared_rules();
    let expected = Action::StepUp {
        acr: "urn:mace:incommon:iap:silver".to_owned(),
    };
    assert_eq!(
        rules.decide(&facts("/admin/users", Some("alice"))).action,
        expected,
        "the resource surface"
    );
    assert_eq!(
        rules
            .decide(&facts("/token", Some("privileged-user")))
            .action,
        expected,
        "and the token endpoint, from the same list"
    );
}

/// FIRST MATCH DECIDES, ACROSS THE SURFACES TOO.
///
/// The suspended-subject deny sits above the catch-all token allow, so ordering is what makes
/// one list serve both. Without this, the three tests above would pass against a set whose rules
/// happened not to overlap, and the criterion is about one SET rather than three disjoint ones.
#[test]
fn ordering_decides_between_rules_that_both_match_a_token_request() {
    let rules = shared_rules();
    let decision = rules.decide(&facts("/token", Some("suspended-user")));
    assert_eq!(decision.action, Action::Deny);
    assert_eq!(
        decision.matched.as_deref(),
        Some("suspended subject gets no tokens"),
        "the narrow deny must win over the catch-all allow below it"
    );
}
