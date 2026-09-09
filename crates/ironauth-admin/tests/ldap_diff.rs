// SPDX-License-Identifier: MIT OR Apache-2.0

//! Deciding who joined and who left between two directory reads (issue #142).

use std::collections::BTreeSet;

use ironauth_admin::ldap_diff::{DepartureRefusal, Diff};
use ironauth_admin::ldap_groups::{GroupSource, Member, expand};

struct Graph {
    edges: std::collections::BTreeMap<String, Vec<Member>>,
}

impl Graph {
    fn new(edges: &[(&str, &[(&str, bool)])]) -> Self {
        Self {
            edges: edges
                .iter()
                .map(|(g, ms)| {
                    (
                        (*g).to_owned(),
                        ms.iter()
                            .map(|(dn, is_group)| Member {
                                dn: (*dn).to_owned(),
                                is_group: *is_group,
                            })
                            .collect(),
                    )
                })
                .collect(),
        }
    }
}

impl GroupSource for Graph {
    type Error = String;

    async fn direct_members(&self, group_dn: &str) -> Result<Vec<Member>, String> {
        Ok(self.edges.get(group_dn).cloned().unwrap_or_default())
    }
}

fn person(dn: &str) -> (&str, bool) {
    (dn, false)
}
fn group(dn: &str) -> (&str, bool) {
    (dn, true)
}

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

/// The ordinary case: one arrival, one departure, one who stayed.
#[test]
fn a_complete_read_yields_arrivals_and_departures() {
    let diff = Diff::between(&set(&["ada", "grace"]), &set(&["grace", "alan"]), true);
    assert_eq!(*diff.arrivals(), set(&["alan"]));
    assert_eq!(*diff.departures().expect("complete read"), set(&["ada"]));
    assert_eq!(*diff.retained(), set(&["grace"]));
}

#[expect(
    clippy::disallowed_methods,
    reason = "asserting on the provisional set is exactly what these tests are for: the lint \
              exists to keep a deprovisioning caller off it, not a test that pins its contents"
)]
/// THE ASYMMETRY. An incomplete read still yields arrivals and refuses departures.
///
/// A short read can only under-report an arrival, and a late joiner signs in tomorrow. A leaver
/// concluded from a short read is a person deactivated or deleted, and every way a read comes
/// back short -- a truncated group walk above all -- looks exactly like a departure.
#[test]
fn an_incomplete_read_gives_arrivals_but_refuses_departures() {
    let diff = Diff::between(&set(&["ada", "grace"]), &set(&["grace", "alan"]), false);

    assert_eq!(
        *diff.arrivals(),
        set(&["alan"]),
        "an arrival is safe to act on from a short read"
    );
    assert_eq!(
        diff.departures().expect_err("must refuse"),
        DepartureRefusal::ObservationIncomplete
    );
    // THE OTHER DIRECTION. The only other mention of this accessor asserts `true` about a diff
    // built with `complete = true`, so replacing the body with a constant `true` left the whole
    // suite green. A health page has to call this to say "12 would be deprovisioned once the
    // bound is raised", and an accessor stuck at true means that banner never fires.
    assert!(
        !diff.observation_was_complete(),
        "the accessor must report the incompleteness this diff was built with"
    );

    // The set still EXISTS for reporting -- an operator wants to know what is pending -- it is
    // simply not reachable through the accessor a deprovisioning cascade would call.
    assert_eq!(*diff.provisional_departures(), set(&["ada"]));
}

#[expect(
    clippy::disallowed_methods,
    reason = "asserting on the provisional set is exactly what these tests are for: the lint \
              exists to keep a deprovisioning caller off it, not a test that pins its contents"
)]
/// A read that returns NOBODY is a failed read, not a company that fired everybody.
///
/// A base DN typo, a revoked read grant and a renamed group all produce a technically successful
/// search with zero results. Row by row it is indistinguishable from total departure, and acting
/// on it deprovisions the whole directory in one pass.
#[test]
fn a_read_that_returns_nobody_is_refused_even_when_it_is_complete() {
    let diff = Diff::between(&set(&["ada", "grace", "alan"]), &BTreeSet::new(), true);
    assert_eq!(
        diff.departures().expect_err("must refuse"),
        DepartureRefusal::EverybodyVanished { previously: 3 }
    );
    assert!(
        diff.observation_was_complete(),
        "the refusal must not depend on the read being incomplete: this one was complete"
    );
    assert_eq!(diff.provisional_departures().len(), 3);
}

/// An empty directory that was ALREADY empty is not a wipe, and must not be refused.
///
/// Without this the guard above would be satisfied by the degenerate case and a connector
/// pointed at a genuinely empty OU would error on every run forever.
#[test]
fn an_empty_read_against_an_empty_snapshot_is_fine() {
    let diff = Diff::between(&BTreeSet::new(), &BTreeSet::new(), true);
    assert!(
        diff.departures()
            .expect("no previous people to lose")
            .is_empty()
    );
}

/// Everybody legitimately leaving except one person is NOT the wipe case.
///
/// The guard keys on the read returning nothing, not on the departure count being large, so a
/// real mass departure that leaves anybody behind still goes through. Pins that the check is the
/// one described rather than a threshold on how many left.
#[test]
fn a_near_total_departure_that_still_returns_somebody_is_allowed() {
    let previous = set(&["a", "b", "c", "d", "e"]);
    let diff = Diff::between(&previous, &set(&["e"]), true);
    assert_eq!(
        *diff.departures().expect("a non-empty read is actionable"),
        set(&["a", "b", "c", "d"])
    );
}

/// A first run has no previous snapshot, so everybody is an arrival and nobody left.
#[test]
fn a_first_run_is_all_arrivals() {
    let diff = Diff::between(&BTreeSet::new(), &set(&["ada", "grace"]), true);
    assert_eq!(*diff.arrivals(), set(&["ada", "grace"]));
    assert!(diff.departures().expect("nothing to lose").is_empty());
}

/// An incomplete read that returns nobody reports the INCOMPLETENESS, which is the more
/// actionable of the two: raising the bound is a fix, investigating a wipe is a hunt.
#[test]
fn incompleteness_is_reported_ahead_of_the_wipe() {
    let diff = Diff::between(&set(&["ada"]), &BTreeSet::new(), false);
    assert_eq!(
        diff.departures().expect_err("must refuse"),
        DepartureRefusal::ObservationIncomplete
    );
}

/// Nothing changed between two complete reads.
#[test]
fn an_unchanged_directory_produces_no_movement() {
    let people = set(&["ada", "grace"]);
    let diff = Diff::between(&people, &people, true);
    assert!(diff.arrivals().is_empty());
    assert!(diff.departures().expect("complete").is_empty());
    assert_eq!(*diff.retained(), people);
}

#[expect(
    clippy::disallowed_methods,
    reason = "asserting on the provisional set is exactly what these tests are for: the lint \
              exists to keep a deprovisioning caller off it, not a test that pins its contents"
)]
/// The expansion and its completeness travel together.
///
/// `Diff::between` takes a bare `bool`, so `Diff::between(&previous, &members, true)` compiled
/// fine and silently disabled the refusal on a truncated walk. `against` takes the
/// [`Expansion`] itself, so the flag cannot be supplied separately from the member set it
/// describes -- which is also what finally makes `Expansion::complete` read by something other
/// than its own tests.
#[tokio::test]
async fn a_truncated_expansion_refuses_departures_through_the_real_connection() {
    let graph = Graph::new(&[
        ("root", &[person("stays"), group("nested")]),
        ("nested", &[person("hidden")]),
    ]);
    let truncated = expand(&graph, &["root".to_owned()], 0)
        .await
        .expect("expands");
    assert!(!truncated.complete, "the fixture must actually truncate");

    let previously = set(&["stays", "hidden"]);
    let diff = Diff::against(&previously, &truncated);

    assert_eq!(
        diff.departures()
            .expect_err("a truncated walk cannot name departures"),
        DepartureRefusal::ObservationIncomplete
    );
    assert!(!diff.observation_was_complete());
    // `hidden` is behind the cut, so it LOOKS departed and must not be reported as one.
    assert!(diff.provisional_departures().contains("hidden"));

    // AND THE CONTRAST: the same graph fully expanded names nobody as departed.
    let whole = expand(&graph, &["root".to_owned()], 5)
        .await
        .expect("expands");
    assert!(whole.complete);
    let diff = Diff::against(&previously, &whole);
    assert!(
        diff.departures()
            .expect("a complete walk is actionable")
            .is_empty(),
        "nobody left; the fixture only hid them behind the bound"
    );
}
