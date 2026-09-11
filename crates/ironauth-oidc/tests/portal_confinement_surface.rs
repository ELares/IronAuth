// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every portal panel that reads organization state is NAMED against the test that fences it
//! (issue #140, acceptance criterion 3).
//!
//! # Why a named registry and not an inferred one
//!
//! Criterion 3 asks for "the IDOR harness extended to portal APIs", and the harness cannot
//! take the portal's organization axis: an `IsolationProbe` varies the tenant and the
//! environment, because `Scope` carries nothing else. `idor_harness.rs` says so where a reader
//! looking for the portal will find it. What that leaves is an inventory, and an inventory
//! nothing checks is the shape this project keeps shipping.
//!
//! THE FIRST VERSION OF THIS FILE INFERRED THE INVENTORY and was wrong for half of it. It
//! called a panel covered when some test in `portal_route.rs` seeded two organizations and
//! mentioned the panel. Seeding two organizations is not crossing a boundary. A review
//! reproduced the consequence: with all five genuine isolation tests deleted, the scan still
//! reported `scim` covered by `no_guide_is_offered_for_work_that_cannot_succeed` -- which
//! seeds one organization in each of TWO DEPLOYMENTS and is about setup guides -- and
//! `certificate-renewal` covered by `two_organizations_pasting_the_same_certificate_are_both_pinned`,
//! an outbox idempotency test in which neither organization ever touches the other's state.
//! Only `contacts` went red. A guard that licenses a claim it cannot support is worse than the
//! prose it replaced, because the prose does not look checked.
//!
//! So the mapping below is WRITTEN DOWN. A person decides which test fences a panel; this file
//! checks that the decision has been made for every panel and that the test named still exists.
//!
//! # What it therefore does and does not prove
//!
//! It proves: every panel `surface_get` dispatches to appears here; every test named here is a
//! live `#[tokio::test]` in `portal_route.rs`; and the scan still recognises the dispatch it is
//! reading. A panel added tomorrow fails this file until somebody names its test, and deleting
//! or renaming a named test fails it the same day.
//!
//! It does NOT prove that a named test asserts isolation, that its assertion would fail if the
//! fence were removed, or that a panel has no second unfenced read. A text scan cannot see any
//! of that, and the previous version's attempt to is why this one does not try. The mutation
//! results recorded on the pull request own it: every test named here was measured by removing
//! the organization predicate it guards and confirming it turns red.
//!
//! `ironauth-admin/tests/org_confinement_surface.rs` is this idea for the management plane,
//! including the part where it states plainly what its scan cannot see.

use std::collections::BTreeSet;

/// The handler source, read as text so a panel added tomorrow is seen without editing a list.
const SURFACE_SRC: &str = include_str!("../src/portal_route.rs");

/// The suite the named tests must live in.
const SURFACE_TESTS: &str = include_str!("portal_route.rs");

/// Each panel, and the test that proves one organization's session cannot read another's
/// state through it.
///
/// Each was measured by removing the organization predicate it guards; see the pull request
/// for #140 criterion 3. Adding a panel means adding a row, and adding a row means having a
/// test to name.
const PANEL_COVERAGE: &[(&str, &str)] = &[
    (
        "scim",
        "a_portal_session_sees_only_its_own_organizations_connections",
    ),
    (
        "certificate-renewal",
        "a_renewal_session_sees_only_its_own_organizations_connections",
    ),
    (
        "contacts",
        "a_contacts_session_sees_only_its_own_organizations_contacts",
    ),
    (
        "audit",
        "the_audit_page_shows_this_organizations_events_and_no_others",
    ),
];

/// The body of `surface_get`, which is the dispatch this file is about.
fn dispatch_body() -> &'static str {
    let at = SURFACE_SRC
        .find("pub async fn surface_get(")
        .expect("surface_get is the portal's panel dispatch and it is gone");
    let rest = &SURFACE_SRC[at..];
    let end = rest.find("\n}\n").map_or(rest.len(), |e| e + 2);
    &rest[..end]
}

/// Every intent the dispatch compares against, as it spells them.
fn dispatched_intents() -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let body = dispatch_body();
    let mut rest = body;
    while let Some(at) = rest.find("intent == \"") {
        let after = &rest[at + "intent == \"".len()..];
        let Some(close) = after.find('"') else { break };
        found.insert(after[..close].to_owned());
        rest = &after[close..];
    }
    found
}

/// Every panel function the dispatch hands off to.
///
/// Counted SEPARATELY from the intent literals on purpose. The literal scan recognises one
/// shape, `if intent == "x"`, and a future arm written as a `match` would be invisible to it
/// while still calling a panel. Comparing the two counts is what makes that visible: the scan
/// goes red saying it no longer recognises the dispatch, rather than quietly measuring a
/// shrinking fraction of it.
fn dispatched_panel_fns() -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let body = dispatch_body();
    for (index, _) in body.match_indices("_surface(") {
        let head = &body[..index];
        let start = head
            .rfind(|c: char| !c.is_alphanumeric() && c != '_')
            .map_or(0, |p| p + 1);
        found.insert(format!("{}_surface", &body[start..index]));
    }
    found
}

/// Whether `name` is a live test in the portal suite.
fn is_live_test(name: &str) -> bool {
    let needle = format!("\nasync fn {name}(");
    let Some(at) = SURFACE_TESTS.find(&needle) else {
        return false;
    };
    SURFACE_TESTS[..at].ends_with("#[tokio::test]")
}

/// Whether `panel_fn`'s body reads state bounded by the session's organization.
fn reads_organization_state(panel_fn: &str) -> bool {
    let needle = format!("async fn {panel_fn}(");
    let Some(at) = SURFACE_SRC.find(&needle) else {
        panic!("{panel_fn} is dispatched but not defined in portal_route.rs");
    };
    let rest = &SURFACE_SRC[at..];
    let end = rest.find("\n}\n").map_or(rest.len(), |e| e + 2);
    rest[..end].contains("session.organization()")
}

#[test]
fn the_scan_still_recognises_the_dispatch_it_reads() {
    let intents = dispatched_intents();
    let panels = dispatched_panel_fns();
    // THE DENOMINATOR IS ASSERTED NON-EMPTY FIRST, because every comparison below is
    // satisfied by two empty sets, and that is what a renamed `surface_get` produces.
    assert!(
        !panels.is_empty(),
        "no panel function was found in the dispatch, so this file proved nothing"
    );
    assert_eq!(
        intents.len(),
        panels.len(),
        "the dispatch has {} intent literals and {} panel calls, so this scan is no longer \
         reading all of it -- a panel written in a shape the literal scan misses is exactly \
         what this comparison exists to surface. intents: {intents:?}, panels: {panels:?}",
        intents.len(),
        panels.len()
    );
}

#[test]
fn every_panel_reading_organization_state_is_named_against_a_live_test() {
    let intents = dispatched_intents();
    let named: BTreeSet<&str> = PANEL_COVERAGE.iter().map(|(intent, _)| *intent).collect();

    let mut reading = Vec::new();
    for intent in &intents {
        // The panel function for this intent, by the arm that returns it.
        let marker = format!("intent == \"{intent}\"");
        let body = dispatch_body();
        let at = body.find(&marker).expect("the arm was just found");
        let tail = &body[at..];
        let call = tail.find("_surface(").expect("an arm returns a panel");
        let head = &tail[..call];
        let start = head
            .rfind(|c: char| !c.is_alphanumeric() && c != '_')
            .map_or(0, |p| p + 1);
        let panel_fn = format!("{}_surface", &head[start..]);
        if reads_organization_state(&panel_fn) {
            reading.push(intent.clone());
        }
    }

    assert!(
        !reading.is_empty(),
        "no panel was seen to read organization state, so this scan proved nothing -- \
         `session.organization()` has probably been renamed"
    );
    let unnamed: Vec<&String> = reading
        .iter()
        .filter(|intent| !named.contains(intent.as_str()))
        .collect();
    assert!(
        unnamed.is_empty(),
        "these portal panels read organization state and no test is named against them in \
         PANEL_COVERAGE: {unnamed:?} (of {reading:?})"
    );
}

#[test]
fn every_named_test_still_exists() {
    // A row naming a test that was renamed or deleted is a row asserting nothing, and it
    // would keep the check above green forever.
    let missing: Vec<&str> = PANEL_COVERAGE
        .iter()
        .filter(|(_, test)| !is_live_test(test))
        .map(|(_, test)| *test)
        .collect();
    assert!(
        missing.is_empty(),
        "PANEL_COVERAGE names tests that are not live #[tokio::test] functions in \
         portal_route.rs: {missing:?}"
    );
}

#[test]
fn no_panel_is_named_twice_and_none_is_stale() {
    let intents = dispatched_intents();
    let stale: Vec<&str> = PANEL_COVERAGE
        .iter()
        .map(|(intent, _)| *intent)
        .filter(|intent| !intents.contains(*intent))
        .collect();
    assert!(
        stale.is_empty(),
        "PANEL_COVERAGE names intents the dispatch no longer serves: {stale:?}"
    );
    let unique: BTreeSet<&str> = PANEL_COVERAGE.iter().map(|(intent, _)| *intent).collect();
    assert_eq!(
        unique.len(),
        PANEL_COVERAGE.len(),
        "an intent appears twice in PANEL_COVERAGE, so one of its rows is not being read"
    );
}
