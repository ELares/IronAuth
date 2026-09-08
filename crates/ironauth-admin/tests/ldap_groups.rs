// SPDX-License-Identifier: MIT OR Apache-2.0

//! Expanding nested directory groups (issue #142).

use std::collections::BTreeMap;
use std::sync::Mutex;

use ironauth_admin::ldap_groups::{GroupSource, Member, expand};

/// A fixed group graph, which is how a cycle and a 40-deep nesting get tested at all.
struct Graph {
    edges: BTreeMap<String, Vec<Member>>,
    /// Every group queried, in order, so a test can prove the walk did not re-query.
    queried: Mutex<Vec<String>>,
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
            queried: Mutex::new(Vec::new()),
            fail_on: None,
        }
    }
}

impl GroupSource for Graph {
    type Error = String;

    async fn direct_members(&self, group_dn: &str) -> Result<Vec<Member>, String> {
        self.queried.lock().expect("lock").push(group_dn.to_owned());
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
#[tokio::test]
async fn a_membership_cycle_terminates_and_still_finds_everyone() {
    let graph = Graph::new(&[
        ("all-staff", &[group("engineering"), person("ada")]),
        ("engineering", &[group("all-staff"), person("grace")]),
    ]);
    let out = expand(&graph, &["all-staff".to_owned()], 10)
        .await
        .expect("expands");

    assert_eq!(
        out.members,
        ["ada".to_owned(), "grace".to_owned()].into_iter().collect()
    );
    // Each group read exactly once, which is what stops the cycle rather than luck.
    assert_eq!(graph.queried.lock().expect("lock").len(), 2);
    assert!(out.revisited.contains("all-staff"));
}

/// A CYCLE IS NOT INCOMPLETENESS.
///
/// The group closing the cycle was already visited, so the walk really did see the whole graph.
/// Reporting it as truncated would make a caller that refuses to deprovision on incomplete data
/// refuse forever, and the connector would never converge on a directory containing one
/// perfectly legal back-edge.
#[tokio::test]
async fn a_cycle_does_not_make_the_expansion_incomplete() {
    let graph = Graph::new(&[
        ("a", &[group("b"), person("one")]),
        ("b", &[group("a"), person("two")]),
    ]);
    let out = expand(&graph, &["a".to_owned()], 10)
        .await
        .expect("expands");
    assert!(out.complete, "a fully explored cyclic graph is complete");
    assert!(out.truncated_at.is_empty());
}

/// A diamond is acyclic, legal, and would expand exponentially without the visited set.
#[tokio::test]
async fn a_diamond_is_complete_and_each_group_is_read_once() {
    let graph = Graph::new(&[
        ("top", &[group("left"), group("right")]),
        ("left", &[group("bottom")]),
        ("right", &[group("bottom")]),
        ("bottom", &[person("deep")]),
    ]);
    let out = expand(&graph, &["top".to_owned()], 10)
        .await
        .expect("expands");
    assert!(out.complete);
    assert_eq!(out.members, ["deep".to_owned()].into_iter().collect());
    assert_eq!(
        graph.queried.lock().expect("lock").len(),
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
#[tokio::test]
async fn a_depth_bound_that_cuts_the_walk_reports_an_incomplete_expansion() {
    let graph = Graph::new(&[
        ("root", &[person("shallow"), group("nested")]),
        ("nested", &[person("hidden")]),
    ]);
    let out = expand(&graph, &["root".to_owned()], 0)
        .await
        .expect("expands");

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
#[tokio::test]
async fn a_zero_bound_returns_direct_members_and_descends_no_further() {
    let graph = Graph::new(&[
        ("root", &[person("a"), person("b"), group("sub")]),
        ("sub", &[person("c")]),
    ]);
    let out = expand(&graph, &["root".to_owned()], 0)
        .await
        .expect("expands");
    assert_eq!(
        out.members,
        ["a".to_owned(), "b".to_owned()].into_iter().collect()
    );
    assert_eq!(out.depth_reached, 0);
    assert_eq!(
        graph.queried.lock().expect("lock").as_slice(),
        ["root".to_owned()]
    );
}

/// One more hop than the graph needs is complete; one fewer is not. The pair pins the bound to
/// the exact hop, where asserting only the deep case would pass for an off-by-one in either
/// direction.
#[tokio::test]
async fn the_bound_is_exact_at_the_hop_it_names() {
    let graph = Graph::new(&[
        ("l0", &[group("l1")]),
        ("l1", &[group("l2")]),
        ("l2", &[person("bottom")]),
    ]);

    let short = expand(&graph, &["l0".to_owned()], 1)
        .await
        .expect("expands");
    assert!(!short.complete, "two hops are needed and one was allowed");
    assert!(!short.members.contains("bottom"));

    let exact = expand(&graph, &["l0".to_owned()], 2)
        .await
        .expect("expands");
    assert!(exact.complete);
    assert_eq!(exact.members, ["bottom".to_owned()].into_iter().collect());
    assert_eq!(exact.depth_reached, 2);
}

/// Several roots expand together and deduplicate.
#[tokio::test]
async fn overlapping_roots_are_read_once_each() {
    let graph = Graph::new(&[
        ("r1", &[group("shared"), person("only1")]),
        ("r2", &[group("shared"), person("only2")]),
        ("shared", &[person("common")]),
    ]);
    let out = expand(&graph, &["r1".to_owned(), "r2".to_owned()], 5)
        .await
        .expect("expands");
    assert_eq!(
        out.members,
        ["common".to_owned(), "only1".to_owned(), "only2".to_owned()]
            .into_iter()
            .collect()
    );
    assert_eq!(graph.queried.lock().expect("lock").len(), 3);
}

/// A failing query aborts rather than returning the half of the graph it managed to read.
///
/// Half a member set is precisely the input that must not reach a deprovisioning comparison, and
/// an error is much harder to ignore than a `complete: false` a caller might forget to check.
#[tokio::test]
async fn a_directory_error_aborts_instead_of_returning_a_partial_set() {
    let mut graph = Graph::new(&[
        ("root", &[person("visible"), group("broken")]),
        ("broken", &[person("never-seen")]),
    ]);
    graph.fail_on = Some("broken".to_owned());
    let err = expand(&graph, &["root".to_owned()], 5)
        .await
        .expect_err("must fail");
    assert_eq!(err, "directory refused broken");
}

/// A root the directory does not know is an empty expansion, not a panic or an error: a group
/// deleted between two syncs is ordinary.
#[tokio::test]
async fn an_unknown_root_expands_to_nobody() {
    let graph = Graph::new(&[]);
    let out = expand(&graph, &["gone".to_owned()], 5)
        .await
        .expect("expands");
    assert!(out.members.is_empty());
    assert!(out.complete);
    assert_eq!(
        out.groups_visited,
        ["gone".to_owned()].into_iter().collect()
    );
}

/// A SHORTCUT EDGE AT THE BOUND MUST NOT READ AS TRUNCATION.
///
/// `root` lists both `engineering` and the company-wide `all-staff`, and `engineering` also lists
/// `all-staff` -- the ordinary shape of a real directory. At `max_depth = 1` the second edge to
/// `all-staff` arrives while `all-staff` is sitting in the queue, unpopped.
///
/// The first version recorded that as truncation, because membership was only written when a
/// group was POPPED, so a queued group was invisible to the already-reached check. It reported
/// `complete = false` and named `all-staff` as unexplored on a run that read `all-staff` moments
/// later -- precisely the "refuse forever, never converge" failure the module is built to avoid,
/// arriving through the code meant to prevent it.
#[tokio::test]
async fn a_second_edge_to_a_queued_group_is_not_truncation() {
    let graph = Graph::new(&[
        ("root", &[group("engineering"), group("all-staff")]),
        ("engineering", &[group("all-staff"), person("grace")]),
        ("all-staff", &[person("ada")]),
    ]);
    let out = expand(&graph, &["root".to_owned()], 1)
        .await
        .expect("expands");

    assert!(
        out.complete,
        "every group was read, so this walk was complete; truncated_at={:?}",
        out.truncated_at
    );
    assert!(out.truncated_at.is_empty());
    assert_eq!(
        out.members,
        ["ada".to_owned(), "grace".to_owned()].into_iter().collect()
    );
    assert!(
        out.revisited.contains("all-staff"),
        "all-staff was reached twice and must be reported as such: {:?}",
        out.revisited
    );
}

/// THE SAME GRAPH IN THE OTHER MEMBER ORDER MUST GIVE THE SAME ANSWER.
///
/// The bug above was order-dependent: listing `all-staff` before `engineering` happened to
/// produce a correct result, so half the orderings hid it. LDAP does not promise a stable order
/// for a multi-valued `member`, and a connector must not report complete on one poll and
/// incomplete on the next because a directory re-indexed.
#[tokio::test]
async fn the_verdict_does_not_depend_on_the_order_members_are_listed_in() {
    let forwards = Graph::new(&[
        ("root", &[group("engineering"), group("all-staff")]),
        ("engineering", &[group("all-staff"), person("grace")]),
        ("all-staff", &[person("ada")]),
    ]);
    let backwards = Graph::new(&[
        ("root", &[group("all-staff"), group("engineering")]),
        ("engineering", &[group("all-staff"), person("grace")]),
        ("all-staff", &[person("ada")]),
    ]);

    let a = expand(&forwards, &["root".to_owned()], 1)
        .await
        .expect("expands");
    let b = expand(&backwards, &["root".to_owned()], 1)
        .await
        .expect("expands");

    assert_eq!(a.complete, b.complete, "member order changed the verdict");
    assert_eq!(a.members, b.members);
    assert_eq!(a.truncated_at, b.truncated_at);
    assert!(a.complete);
}

/// One configured root nested inside another, at the degenerate bound.
///
/// `all-staff` is both a root in its own right and a member of the root `engineering`. At
/// `max_depth = 0` nothing should be descended into, and both roots are read regardless -- so
/// naming `all-staff` as unexplored would be wrong on a run that read it.
#[tokio::test]
async fn a_root_that_is_also_a_member_of_another_root_is_not_truncation() {
    let graph = Graph::new(&[
        ("engineering", &[group("all-staff"), person("grace")]),
        ("all-staff", &[person("ada")]),
    ]);
    let out = expand(
        &graph,
        &["engineering".to_owned(), "all-staff".to_owned()],
        0,
    )
    .await
    .expect("expands");

    assert!(
        out.complete,
        "both roots were read; truncated_at={:?}",
        out.truncated_at
    );
    assert_eq!(
        out.members,
        ["ada".to_owned(), "grace".to_owned()].into_iter().collect()
    );
}

/// THE SAME ROOT LISTED TWICE IS READ ONCE.
///
/// A connector's group list is operator-typed, so a duplicate is ordinary. With the push-time
/// `seen` set in place, a duplicate ROOT is the only remaining way a group can reach the queue
/// twice -- `seen` stops every other path -- which makes this the only fixture that exercises
/// the pop-time guard at all. Without it, deleting that guard's `continue` goes unnoticed and
/// the group is read, and billed, twice.
#[tokio::test]
async fn a_root_listed_twice_is_still_read_once() {
    let graph = Graph::new(&[
        ("team", &[person("ada"), group("sub")]),
        ("sub", &[person("bo")]),
    ]);
    let out = expand(&graph, &["team".to_owned(), "team".to_owned()], 5)
        .await
        .expect("expands");

    assert_eq!(
        graph.queried.lock().expect("lock").as_slice(),
        ["team".to_owned(), "sub".to_owned()],
        "a duplicated root must not be read twice"
    );
    assert!(out.complete);
    assert_eq!(
        out.members,
        ["ada".to_owned(), "bo".to_owned()].into_iter().collect()
    );
    assert!(
        out.revisited.contains("team"),
        "the duplicate is a second reach and must be reported: {:?}",
        out.revisited
    );
}
