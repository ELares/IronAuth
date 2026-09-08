// SPDX-License-Identifier: MIT OR Apache-2.0

//! Expanding nested directory groups into the people in them (issue #142).
//!
//! # Why this is not a tree walk
//!
//! LDAP groups form a DIRECTED GRAPH, not a tree, and nothing in the protocol forbids a cycle.
//! `all-staff` contains `engineering`, somebody adds `all-staff` to `engineering` so the mailing
//! list works, and now a naive recursion never returns. Neither Active Directory nor `OpenLDAP`
//! rejects that edge. A depth bound alone does not save a walk either: a diamond
//! (`a` contains `b` and `c`, both of which contain `d`) is acyclic and still expands
//! exponentially without memoisation. So this keeps a visited set, which handles both.
//!
//! # An incomplete expansion must never drive deprovisioning
//!
//! This is the property the module is really built around.
//!
//! A connector carries `max_group_depth`, and a directory deeper than that bound yields a
//! PARTIAL member set. Partial in one direction only: people are missing, never invented. That
//! sounds fail-safe and is the opposite, because of what consumes it. The sync compares the set
//! returned here against who is currently provisioned and treats anybody missing as departed --
//! and under `absence_policy = delete`, deletes them.
//!
//! So a truncated expansion looks exactly like a mass departure. LOWERING `max_group_depth`, or
//! adding a layer of nesting in the directory, would deprovision everybody below the cut -- the
//! worst outcome this subsystem can produce, arriving without a single error. Raising the bound
//! is the SAFE direction and the remedy: the member set is monotone in the bound, so raising it
//! can only add people and can only flip `complete` from false to true.
//!
//! [`Expansion::complete`] therefore reports whether the bound was reached. The type does NOT
//! enforce that a caller looks at it -- every field is public, and nothing here can stop
//! `expansion.members` being read on its own. The enforcement lives one layer up, in
//! `ldap_diff::Diff::departures`, which takes this flag and refuses to name anybody as departed
//! when it is false. That is the layer where the dangerous conclusion is actually drawn, so it
//! is the layer worth making unavoidable; saying the type prevented it here would be a comfort
//! rather than a mechanism.

use std::collections::{BTreeSet, VecDeque};

/// One entry returned as a member of a group.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Member {
    /// The member's distinguished name.
    pub dn: String,
    /// Whether this member is itself a group, and so should be descended into.
    ///
    /// Decided by the caller from the entry's `objectClass`, because the class naming a group
    /// differs by server (`group` on Active Directory, `groupOfNames` and `groupOfUniqueNames`
    /// on `OpenLDAP`) and this module does not want a server dialect baked into it.
    pub is_group: bool,
}

/// Where the members of a group come from.
///
/// A trait so the expansion is testable against a fixed graph, including graphs a real server
/// would be tedious to coax into producing -- a cycle, or nesting deeper than any sane
/// directory.
pub trait GroupSource {
    /// What the source can fail with.
    type Error;

    /// The DIRECT members of one group: no recursion, no transitive members.
    ///
    /// ASYNC, because the only implementation that matters is a network client. Written
    /// synchronously first, this trait was one no real source could implement: `ldap3` is
    /// async throughout, and a blocking shim around it inside a Tokio worker is how a runtime
    /// gets starved.
    ///
    /// # Errors
    ///
    /// Whatever the underlying directory query fails with.
    fn direct_members(
        &self,
        group_dn: &str,
    ) -> impl std::future::Future<Output = Result<Vec<Member>, Self::Error>> + Send;
}

/// The result of expanding one or more group roots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expansion {
    /// The DNs of every non-group member reached, deduplicated and ordered.
    pub members: BTreeSet<String>,
    /// Every group DN visited, including the roots. Useful for reporting and for cache keys.
    pub groups_visited: BTreeSet<String>,
    /// Whether the whole graph was explored.
    ///
    /// FALSE means the depth bound cut the walk short and [`Self::members`] is missing people.
    /// A caller that deprovisions on absence MUST refuse to act on a false here -- see the module
    /// header for what happens if it does not.
    pub complete: bool,
    /// The group DNs left unexplored when the bound was hit, for the operator's error message.
    pub truncated_at: BTreeSet<String>,
    /// How many hops below the roots the walk actually went.
    pub depth_reached: u32,
    /// Group DNs that were reached more than once, i.e. the graph is not a tree.
    ///
    /// Not an error: a diamond is perfectly legal and common. Reported because a cycle is the
    /// usual cause of a surprising expansion and an operator debugging one wants to see it.
    pub revisited: BTreeSet<String>,
}

/// Expand a set of group roots into the people beneath them.
///
/// `max_depth` counts HOPS BELOW THE ROOTS: zero means the direct members of the roots and no
/// descent into any nested group. The roots themselves are always read, so a zero bound still
/// returns people rather than nothing.
///
/// # Errors
///
/// Propagates the first error from the source. A partial walk is not returned alongside an error:
/// half a member set is exactly the input that must not reach a deprovisioning comparison.
pub async fn expand<S: GroupSource + Sync>(
    source: &S,
    roots: &[String],
    max_depth: u32,
) -> Result<Expansion, S::Error> {
    let mut members = BTreeSet::new();
    let mut groups_visited: BTreeSet<String> = BTreeSet::new();
    let mut revisited = BTreeSet::new();
    let mut truncated_at = BTreeSet::new();
    let mut depth_reached = 0;

    // ENQUEUED, which is not the same as visited, and the difference was a real bug. Membership
    // is recorded in `groups_visited` only when a group is POPPED, so a group sitting in the
    // queue was invisible to the already-reached check below: a second edge arriving at the
    // bound fell through to the depth branch and was recorded as truncation, on a group that got
    // read moments later. The walk then reported `complete = false` for a graph it had explored
    // in full, and which of the two happened depended on the order the server listed members in.
    //
    // Seeded with the roots, because a root can also be a member of another root.
    let mut seen: BTreeSet<String> = roots.iter().cloned().collect();

    // Breadth-first, so `depth_reached` means what it says and the truncation set is exactly the
    // frontier rather than whichever branch a depth-first walk happened to abandon.
    let mut queue: VecDeque<(String, u32)> = roots.iter().map(|dn| (dn.clone(), 0)).collect();

    while let Some((group_dn, depth)) = queue.pop_front() {
        // THE CYCLE GUARD. Also the diamond guard: without it an acyclic graph still blows up.
        if !groups_visited.insert(group_dn.clone()) {
            revisited.insert(group_dn);
            continue;
        }
        depth_reached = depth_reached.max(depth);

        for member in source.direct_members(&group_dn).await? {
            if !member.is_group {
                members.insert(member.dn);
                continue;
            }
            // Already-reached groups are not truncation: they have been expanded, or they are
            // in the queue and will be. Counting them would report an incomplete walk for a
            // graph fully explored, and a caller that refuses to deprovision on incompleteness
            // would then never converge. Testing `seen` rather than `groups_visited` is what
            // makes the "or will be" half of that sentence true.
            if !seen.insert(member.dn.clone()) {
                revisited.insert(member.dn);
                continue;
            }
            if depth >= max_depth {
                truncated_at.insert(member.dn);
                continue;
            }
            queue.push_back((member.dn, depth + 1));
        }
    }

    Ok(Expansion {
        members,
        groups_visited,
        complete: truncated_at.is_empty(),
        truncated_at,
        depth_reached,
        revisited,
    })
}
