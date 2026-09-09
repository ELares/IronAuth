// SPDX-License-Identifier: MIT OR Apache-2.0

//! Translating a plan and a policy into the exact operations a run would perform (issue #142).
//!
//! # Why this is its own layer
//!
//! #142 asks that "dry-run reports the exact change set that a subsequent real run applies". The
//! cheap way to satisfy that is two code paths and a test comparing their output, which holds
//! until somebody edits one of them. The other way is one value: a dry run PRINTS the change set
//! and a real run EXECUTES it, so they cannot disagree because there is only one of them.
//!
//! This module builds that value. It performs no IO and decides nothing about how an operation is
//! carried out -- only what the operations are, in order.
//!
//! # The policy lives here and not in the plan
//!
//! [`crate::ldap_sync::plan`] says who arrived and who is gone. What "gone" DESERVES is the
//! connector's `absence_policy`, and translating it is a separate decision because the two
//! answers need different authority: deactivating is reversible and deleting is not.
//!
//! # A refused departure set produces no departure operations, and says so
//!
//! [`ChangeSet::withheld`] is not a count of nothing. When the plan refused to name departures --
//! a truncated group walk, a read that returned nobody -- the change set carries the refusal so
//! the run that prints it and the run that executes it agree about WHY nothing is being removed.
//! A dry run that silently showed no departures would read as "nobody left".

use std::collections::BTreeSet;

use ironauth_store::LdapAbsencePolicy;

use crate::ldap_diff::DepartureRefusal;
use crate::ldap_sync::SyncPlan;

/// One thing a run would do.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Change {
    /// A principal present in the directory and not in the previous snapshot.
    ///
    /// Carries the stable id rather than the DN: the DN moves when somebody changes team, and
    /// keying provisioning on it is the duplication [`crate::ldap_mapping`] exists to prevent.
    Provision {
        /// The rename-stable identifier.
        stable_id: String,
        /// The login identifier, for the record this creates.
        username: String,
    },
    /// A principal gone from the directory, under a policy that keeps the record.
    Deactivate {
        /// The rename-stable identifier.
        stable_id: String,
    },
    /// A principal gone from the directory, under a policy that does not.
    ///
    /// Separate from [`Self::Deactivate`] rather than a flag on it, because an executor needs
    /// different authority for the two and an operator reading a dry run needs to see which one
    /// is coming. A flag is a thing people skim past.
    Delete {
        /// The rename-stable identifier.
        stable_id: String,
    },
}

/// Everything a run would do, and everything it deliberately would not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeSet {
    /// The operations, in the order an executor should perform them.
    ///
    /// PROVISIONS FIRST. A directory where somebody moved between two synced groups can present
    /// as one departure and one arrival for the same human; doing the arrival first means the
    /// window where they cannot sign in is zero rather than however long the removals take.
    pub changes: Vec<Change>,
    /// Why no departures are included, when that is a refusal rather than an absence.
    pub withheld: Option<DepartureRefusal>,
}

impl ChangeSet {
    /// Work out what a run would do.
    #[must_use]
    pub fn from_plan(plan: &SyncPlan, policy: LdapAbsencePolicy) -> Self {
        let by_stable_id: std::collections::BTreeMap<&str, &str> = plan
            .present
            .iter()
            .map(|p| (p.stable_id.as_str(), p.username.as_str()))
            .collect();

        let mut changes: Vec<Change> = plan
            .arrivals
            .iter()
            .map(|stable_id| Change::Provision {
                stable_id: stable_id.clone(),
                // An arrival is by definition present in this read, so the lookup holds. The
                // fallback is the stable id rather than an empty string: a record created with a
                // blank login is worse than one named after its identifier.
                username: by_stable_id
                    .get(stable_id.as_str())
                    .map_or_else(|| stable_id.clone(), |u| (*u).to_owned()),
            })
            .collect();

        let withheld = match plan.departures.as_ref() {
            Ok(departures) => {
                changes.extend(departures.iter().map(|stable_id| match policy {
                    LdapAbsencePolicy::Deactivate => Change::Deactivate {
                        stable_id: stable_id.clone(),
                    },
                    LdapAbsencePolicy::Delete => Change::Delete {
                        stable_id: stable_id.clone(),
                    },
                }));
                None
            }
            Err(refusal) => Some(*refusal),
        };

        Self { changes, withheld }
    }

    /// The stable ids this run would provision.
    #[must_use]
    pub fn provisions(&self) -> BTreeSet<&str> {
        self.changes
            .iter()
            .filter_map(|c| match c {
                Change::Provision { stable_id, .. } => Some(stable_id.as_str()),
                _ => None,
            })
            .collect()
    }

    /// The stable ids this run would remove, however the policy removes them.
    #[must_use]
    pub fn removals(&self) -> BTreeSet<&str> {
        self.changes
            .iter()
            .filter_map(|c| match c {
                Change::Deactivate { stable_id } | Change::Delete { stable_id } => {
                    Some(stable_id.as_str())
                }
                Change::Provision { .. } => None,
            })
            .collect()
    }

    /// Whether this run would remove anybody irreversibly.
    ///
    /// The question a confirmation prompt asks, and the reason [`Change::Delete`] is its own
    /// variant: a caller should not have to inspect a policy field to learn it.
    #[must_use]
    pub fn deletes_anybody(&self) -> bool {
        self.changes
            .iter()
            .any(|c| matches!(c, Change::Delete { .. }))
    }

    /// Whether this run would do nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }
}
