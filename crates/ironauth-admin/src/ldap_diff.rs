// SPDX-License-Identifier: MIT OR Apache-2.0

//! Deciding who joined and who left between two directory reads (issue #142).
//!
//! # Absence is a conclusion, not an observation
//!
//! A sync sees who IS in the directory. It never sees who left: it infers that from who is
//! missing, and that inference is only as good as the read it is drawn from. Every way a read can
//! come back short -- a depth bound that truncated the group walk, a page that failed, a filter
//! an operator narrowed, a server that answered partially -- looks exactly like a departure.
//!
//! That asymmetry is the whole design here. A joiner arriving late is a person who signs in
//! tomorrow instead of today. A leaver concluded wrongly is a person deactivated, or under
//! `absence_policy = delete`, removed. So this module will compute joiners from an incomplete
//! read and REFUSES to compute leavers from one -- [`Diff::departures`] is not a field, it is a
//! method returning [`Err`]`(`[`DepartureRefusal`]`)` when the read that produced it was short.
//!
//! THE TYPE DOES NOT MAKE THAT UNAVOIDABLE, and an earlier version of this paragraph claimed it
//! did ("there is no way to get the departures out without handling that case"). That was false:
//! [`Diff::provisional_departures`] returns the same set infallibly, which is the whole point of
//! having it, and a three-line caller can reach it. What stops the sync from using it is a
//! `disallowed-methods` entry in `clippy.toml`, so the rule is enforced by the same mechanism
//! the workspace uses for the CEL budget and the LDAP TLS switches -- a lint that fires wherever
//! the call is written, rather than a comment asking nicely.
//!
//! # A run that finds nothing is the shape to fear
//!
//! The dangerous case is not a wrong person, it is EVERY person. A misconfigured base DN, a
//! service account that lost its read grant, a group renamed: all of them return zero members
//! from a technically successful search. That is indistinguishable, row by row, from a company
//! that fired everybody. [`Diff::departures`] therefore also refuses when the read was complete
//! but EMPTY while the previous snapshot was not, and [`DepartureRefusal`] says which of the two
//! it was.

use std::collections::BTreeSet;

use crate::ldap_groups::Expansion;

/// What a previous run recorded, and what this one saw.
#[derive(Debug, Clone)]
pub struct Diff {
    joined: BTreeSet<String>,
    left: BTreeSet<String>,
    unchanged: BTreeSet<String>,
    /// Whether the observation this diff was drawn from saw the whole directory.
    complete: bool,
    /// How many the previous snapshot held, for the wipe check.
    previous_size: usize,
    /// How many the current observation held.
    observed_size: usize,
}

/// Why the departures cannot be acted on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepartureRefusal {
    /// The read was short, so somebody missing may simply not have been looked at.
    ObservationIncomplete,
    /// The read succeeded and returned NOBODY, while the previous run had people.
    ///
    /// Technically a valid answer and almost never the true one: a base DN typo, a revoked read
    /// grant and a renamed group all produce it. Acting on it deprovisions the entire directory
    /// in one pass.
    EverybodyVanished {
        /// How many the previous run had.
        previously: usize,
    },
}

impl std::fmt::Display for DepartureRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ObservationIncomplete => write!(
                f,
                "the directory read was incomplete, so an absent principal may simply not have \
                 been read"
            ),
            Self::EverybodyVanished { previously } => write!(
                f,
                "the read returned nobody while the previous run had {previously}: treat this as \
                 a failed read rather than {previously} departures"
            ),
        }
    }
}

impl Diff {
    /// Compare a previous snapshot against a group expansion.
    ///
    /// THIS IS THE CONNECTION, and it needs to be a function rather than a sentence. The first
    /// version of this module took a bare `bool` and its doc said the flag "comes from the group
    /// expansion" -- which nothing enforced, so `Diff::between(&previous, &members, true)`
    /// compiled fine and silently disabled the refusal on exactly the truncated walk it exists
    /// for. Taking the [`Expansion`] means the completeness travels with the member set it
    /// describes and a caller cannot supply one without the other.
    #[must_use]
    pub fn against(previous: &BTreeSet<String>, observed: &Expansion) -> Self {
        Self::between(previous, &observed.members, observed.complete)
    }

    /// Compare a previous snapshot against a member set and a completeness flag.
    ///
    /// Prefer [`Self::against`], which takes the two together. This exists for a caller that
    /// assembled the member set from something other than one expansion.
    #[must_use]
    pub fn between(
        previous: &BTreeSet<String>,
        observed: &BTreeSet<String>,
        complete: bool,
    ) -> Self {
        Self {
            joined: observed.difference(previous).cloned().collect(),
            left: previous.difference(observed).cloned().collect(),
            unchanged: previous.intersection(observed).cloned().collect(),
            complete,
            previous_size: previous.len(),
            observed_size: observed.len(),
        }
    }

    /// Principals seen now and not before.
    ///
    /// Safe to act on from an incomplete read: a short read can only ever UNDER-report an
    /// arrival, and the cost of a late joiner is that somebody signs in tomorrow.
    #[must_use]
    pub fn arrivals(&self) -> &BTreeSet<String> {
        &self.joined
    }

    /// Principals seen before and not now, or why they cannot be trusted.
    ///
    /// # Errors
    ///
    /// [`DepartureRefusal`] when the observation cannot support the conclusion. A caller must not
    /// route around this by reading [`Self::provisional_departures`] and acting anyway.
    pub fn departures(&self) -> Result<&BTreeSet<String>, DepartureRefusal> {
        if !self.complete {
            return Err(DepartureRefusal::ObservationIncomplete);
        }
        if self.observed_size == 0 && self.previous_size > 0 {
            return Err(DepartureRefusal::EverybodyVanished {
                previously: self.previous_size,
            });
        }
        Ok(&self.left)
    }

    /// The would-be departures, for REPORTING only.
    ///
    /// Named to be unusable by accident, and REFUSED BY CLIPPY outside a reporting surface: the
    /// name alone is not a barrier, and this returns exactly what [`Self::departures`] guards.
    /// A health page saying "12 principals would be deprovisioned once the depth bound is
    /// raised" is worth showing an operator; the same set fed to the deprovisioning cascade is
    /// the outage this module exists to prevent.
    #[must_use]
    pub fn provisional_departures(&self) -> &BTreeSet<String> {
        &self.left
    }

    /// Principals present in both reads.
    #[must_use]
    pub fn retained(&self) -> &BTreeSet<String> {
        &self.unchanged
    }

    /// Whether the observation saw the whole directory.
    #[must_use]
    pub fn observation_was_complete(&self) -> bool {
        self.complete
    }
}
