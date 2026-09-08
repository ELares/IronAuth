// SPDX-License-Identifier: MIT OR Apache-2.0

//! Expanding nested directory groups (issue #142).

use std::cell::RefCell;
use std::collections::BTreeMap;

use ironauth_admin::ldap_groups::{GroupSource, Member, expand};

/// A fixed group graph, which is how a cycle and a 40-deep nesting get tested at all.
struct Graph {
    edges: BTreeMap<String, Vec<Member>>,
    /// Every group queried, in order, so a test can prove the walk did not re-query.
    queried: RefCell<Vec<String>>,
    fail_on: Option<String>,
}

impl Graph {
    fn new(edges: &[(&str, &[(&str, bool)])]) -> Self {
        Self {
            edges: edges
                .iter()
                .map(|(group, members)| {
                    (
                        (*group).to_owned(),
                        members
                            .iter()
                            .map(|(dn, is_group)| Member {
                                dn: (*dn).to_owned(),
                                is_group: *is_group,
                            })
                            .collect(),
                    )
                })
                .collect(),
            queried: RefCell::new(Vec::new()),
            fail_on: None,
        }
    }
}

impl GroupSource for Graph {
    type Error = String;

    fn direct_members(&self, group_dn: &str) -> Result<Vec<Member>, String> {
        self.queried.borrow_mut().push(group_dn.to_owned());
        if self.fail_on.as_deref() == Some(group_dn) {
            return Err(format!("directory refused {group_dn}"));
        }
        Ok(self.edges.get(group_dn).cloned().unwrap_or_default())
    }
}

fn person(dn: &str) -> (&str, bool) {
    (dn, false)
}
fn group(dn: &str) -> (&str, bool) {
    (dn, true)
}

/// THE HEADLINE: a membership cycle terminates.
///
/// `all-staff` contains `engineering` and somebody puts `all-staff` back inside `engineering` so
/// the mailing list works. Nothing in LDAP forbids it and no server rejects it. A naive recursion
/// never returns; this test would hang rather than fail, which is the point.
#[test]
fn a_membership_cycle_terminates_and_still_finds_everyone() {
    let graph = Graph::new(&[
        ("all-staff", &[group("engineering"), person("ada")]),
        ("engineering", &[group("all-staff"), person("grace")]),
    ]);
    let out = expand(&graph, &["all-staff".to_owned()], 10).expect("expands");

    assert_eq!(
        out.members,
        ["ada".to_owned(), "grace".to_owned()].into_iter().collect()
    );
    // Each group read exactly once, which is what stops the cycle rather than luck.
    assert_eq!(graph.queried.borrow().len(), 2);
    assert!(out.revisited.contains("all-staff"));
}

/// A CYCLE IS NOT INCOMPLETENESS.
///
/// The group closing the cycle was already visited, so the walk really did see the whole graph.
/// Reporting it as truncated would make a caller that refuses to deprovision on incomplete data
/// refuse forever, and the connector would never converge on a directory containing one
/// perfectly legal back-edge.
#[test]
fn a_cycle_does_not_make_the_expansion_incomplete() {
    let graph = Graph::new(&[
        ("a", &[group("b"), person("one")]),
        ("b", &[group("a"), person("two")]),
    ]);
    let out = expand(&graph, &["a".to_owned()], 10).expect("expands");
    assert!(out.complete, "a fully explored cyclic graph is complete");
    assert!(out.truncated_at.is_empty());
}

/// A diamond is acyclic, legal, and would expand exponentially without the visited set.
#[test]
fn a_diamond_is_complete_and_each_group_is_read_once() {
    let graph = Graph::new(&[
        ("top", &[group("left"), group("right")]),
        ("left", &[group("bottom")]),
        ("right", &[group("bottom")]),
        ("bottom", &[person("deep")]),
    ]);
    let out = expand(&graph, &["top".to_owned()], 10).expect("expands");
    assert!(out.complete);
    assert_eq!(out.members, ["deep".to_owned()].into_iter().collect());
    assert_eq!(
        graph.queried.borrow().len(),
        4,
        "bottom must be read once, not twice"
    );
    assert!(out.revisited.contains("bottom"));
}

/// THE DANGEROUS CASE. A bound that cuts the walk must say so.
///
/// If this reported `complete`, the sync would compare a short member list against everybody
/// provisioned, read the difference as a mass departure, and under `absence_policy = delete`
/// remove every person below the cut. Adding one layer of nesting in the directory would do it.
#[test]
fn a_depth_bound_that_cuts_the_walk_reports_an_incomplete_expansion() {
    let graph = Graph::new(&[
        ("root", &[person("shallow"), group("nested")]),
        ("nested", &[person("hidden")]),
    ]);
    let out = expand(&graph, &["root".to_owned()], 0).expect("expands");

    assert!(
        !out.complete,
        "a truncated walk reported itself as complete: this deprovisions everybody below the cut"
    );
    assert_eq!(
        out.truncated_at,
        ["nested".to_owned()].into_iter().collect()
    );
    assert!(
        !out.members.contains("hidden"),
        "the fixture must actually hide somebody, or the assertion above proves nothing"
    );
    // And the bound really is a bound rather than a refusal: the shallow member still came back.
    assert!(out.members.contains("shallow"));
}

/// Zero is the degenerate bound and still returns the direct members rather than nothing.
#[test]
fn a_zero_bound_returns_direct_members_and_descends_no_further() {
    let graph = Graph::new(&[
        ("root", &[person("a"), person("b"), group("sub")]),
        ("sub", &[person("c")]),
    ]);
    let out = expand(&graph, &["root".to_owned()], 0).expect("expands");
    assert_eq!(
        out.members,
        ["a".to_owned(), "b".to_owned()].into_iter().collect()
    );
    assert_eq!(out.depth_reached, 0);
    assert_eq!(graph.queried.borrow().as_slice(), ["root".to_owned()]);
}

/// One more hop than the graph needs is complete; one fewer is not. The pair pins the bound to
/// the exact hop, where asserting only the deep case would pass for an off-by-one in either
/// direction.
#[test]
fn the_bound_is_exact_at_the_hop_it_names() {
    let graph = Graph::new(&[
        ("l0", &[group("l1")]),
        ("l1", &[group("l2")]),
        ("l2", &[person("bottom")]),
    ]);

    let short = expand(&graph, &["l0".to_owned()], 1).expect("expands");
    assert!(!short.complete, "two hops are needed and one was allowed");
    assert!(!short.members.contains("bottom"));

    let exact = expand(&graph, &["l0".to_owned()], 2).expect("expands");
    assert!(exact.complete);
    assert_eq!(exact.members, ["bottom".to_owned()].into_iter().collect());
    assert_eq!(exact.depth_reached, 2);
}

/// Several roots expand together and deduplicate.
#[test]
fn overlapping_roots_are_read_once_each() {
    let graph = Graph::new(&[
        ("r1", &[group("shared"), person("only1")]),
        ("r2", &[group("shared"), person("only2")]),
        ("shared", &[person("common")]),
    ]);
    let out = expand(&graph, &["r1".to_owned(), "r2".to_owned()], 5).expect("expands");
    assert_eq!(
        out.members,
        ["common".to_owned(), "only1".to_owned(), "only2".to_owned()]
            .into_iter()
            .collect()
    );
    assert_eq!(graph.queried.borrow().len(), 3);
}

/// A failing query aborts rather than returning the half of the graph it managed to read.
///
/// Half a member set is precisely the input that must not reach a deprovisioning comparison, and
/// an error is much harder to ignore than a `complete: false` a caller might forget to check.
#[test]
fn a_directory_error_aborts_instead_of_returning_a_partial_set() {
    let mut graph = Graph::new(&[
        ("root", &[person("visible"), group("broken")]),
        ("broken", &[person("never-seen")]),
    ]);
    graph.fail_on = Some("broken".to_owned());
    let err = expand(&graph, &["root".to_owned()], 5).expect_err("must fail");
    assert_eq!(err, "directory refused broken");
}

/// A root the directory does not know is an empty expansion, not a panic or an error: a group
/// deleted between two syncs is ordinary.
#[test]
fn an_unknown_root_expands_to_nobody() {
    let graph = Graph::new(&[]);
    let out = expand(&graph, &["gone".to_owned()], 5).expect("expands");
    assert!(out.members.is_empty());
    assert!(out.complete);
    assert_eq!(
        out.groups_visited,
        ["gone".to_owned()].into_iter().collect()
    );
}
