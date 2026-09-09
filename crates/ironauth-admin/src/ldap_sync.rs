// SPDX-License-Identifier: MIT OR Apache-2.0

//! One pass of a directory sync: read, map, expand, compare (issue #142).
//!
//! This is the module that joins the other four. Until it existed they were a connector model, a
//! mapper, a group expansion and a diff, each tested and none of them reachable from anything the
//! binary runs -- which `scripts/dormant-module-scan.sh` said out loud about `ldap_groups` before
//! the diff gave it a caller.
//!
//! # It plans, it does not apply
//!
//! [`plan`] returns what a run WOULD do and writes nothing. That split is not tidiness. The
//! decision it produces -- who has left -- is the one that deactivates or deletes people, and it
//! is drawn from an inference rather than an observation: the directory tells us who is present,
//! and absence is concluded. Every way a read can come back short looks exactly like a departure.
//!
//! So the plan carries [`SyncPlan::departures`] as a [`Result`], and the refusal travels with it.
//! An applier that wants to deprovision has to handle [`DepartureRefusal`]; one that only wants to
//! provision arrivals never has to look. The two halves of the decision have different blast
//! radii and the type says so.
//!
//! # What a caller still has to decide
//!
//! Nothing here writes, audits, or announces. It also does not decide what an absent principal
//! DESERVES -- that is the connector's `absence_policy`, and it belongs to the applier, because
//! "deactivate" and "delete" need different authority and different audit actions.

use std::collections::BTreeSet;

use crate::ldap_client::DirectoryError;
use crate::ldap_diff::{DepartureRefusal, Diff};
use crate::ldap_groups::{GroupSource, expand};
use crate::ldap_mapping::{
    DirectoryEntry, LdapMappingError, MappedPrincipal, attributes_to_request, principal_for,
};

/// Where one pass reads its entries from.
///
/// Separate from [`GroupSource`] because the two answer different questions, and a pass needs
/// both: this one enumerates the people, that one walks the groups they belong to.
pub trait EntrySource {
    /// What the source can fail with.
    type Error;

    /// Every entry under `base` matching `filter`, with `attributes` requested by name.
    ///
    /// `attributes` must come from [`attributes_to_request`]: the identifier attributes are
    /// OPERATIONAL and a search that does not name them does not receive them, which would make
    /// every entry look like it had no stable id.
    ///
    /// # Errors
    ///
    /// Whatever the underlying directory query fails with.
    fn search(
        &self,
        base: &str,
        filter: &str,
        attributes: &[String],
    ) -> impl std::future::Future<Output = Result<Vec<DirectoryEntry>, Self::Error>> + Send;
}

/// What one pass needs from the connector row.
#[derive(Debug, Clone)]
pub struct SyncInputs {
    /// Where to look for people.
    pub user_base_dn: String,
    /// Which of them count.
    pub user_filter: String,
    /// The group DNs whose membership decides access, if any.
    pub group_roots: Vec<String>,
    /// How deep to follow nested groups.
    pub max_group_depth: u32,
    /// The connector's `attribute_mapping`.
    pub attribute_mapping: serde_json::Value,
}

/// Why a pass could not produce a plan at all.
#[derive(Debug)]
pub enum SyncError {
    /// The directory read failed.
    Directory(DirectoryError),
    /// An entry could not be mapped.
    ///
    /// Fatal for the PASS rather than skipped for the entry: a mapping fault is a configuration
    /// fault and it applies to every entry alike, so skipping the ones that trip it would silently
    /// shrink the member set -- which the diff would then read as departures.
    Mapping {
        /// The entry that could not be mapped.
        dn: String,
        /// Why.
        error: LdapMappingError,
    },
    /// Two entries claimed the same stable identifier.
    ///
    /// Not a mapping fault -- each entry mapped fine -- and not survivable: whichever one is
    /// written second silently overwrites the first, and the loser then looks departed on the
    /// next pass.
    DuplicateStableId {
        /// The identifier both entries carried.
        stable_id: String,
        /// The two entries that carried it.
        dns: [String; 2],
    },
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Directory(e) => write!(f, "the directory read failed: {e}"),
            Self::Mapping { dn, error } => write!(f, "{dn} could not be mapped: {error}"),
            Self::DuplicateStableId { stable_id, dns } => write!(
                f,
                "{} and {} both claim the identifier {stable_id}, so one would overwrite the other",
                dns[0], dns[1]
            ),
        }
    }
}

impl std::error::Error for SyncError {}

/// What a pass WOULD do.
#[derive(Debug, Clone)]
pub struct SyncPlan {
    /// Everybody the directory currently says is present, mapped.
    pub present: Vec<MappedPrincipal>,
    /// Stable ids seen now and not in the previous snapshot.
    pub arrivals: BTreeSet<String>,
    /// Stable ids in both.
    pub retained: BTreeSet<String>,
    /// Stable ids in the previous snapshot and not now -- or why that cannot be concluded.
    ///
    /// A [`Result`] rather than a set, so an applier that deprovisions cannot reach the list
    /// without meeting the refusal. See the module header.
    pub departures: Result<BTreeSet<String>, DepartureRefusal>,
    /// How many present principals are identified by their DN rather than a UUID.
    ///
    /// A DEGRADED COUNT, worth surfacing rather than burying: on those the directory offers no
    /// rename-stable handle, so a move or a rename will read as a departure plus an arrival. A
    /// non-zero value here is usually a search that forgot to request the identifier attributes,
    /// which is why [`attributes_to_request`] derives them.
    pub rename_fragile: usize,
    /// Whether the group walk saw the whole graph.
    pub groups_complete: bool,
    /// Group DNs the depth bound left unexplored.
    pub groups_truncated_at: BTreeSet<String>,
}

/// Read the directory once and work out what a sync would do.
///
/// Writes nothing.
///
/// # Errors
///
/// [`SyncError`] when the pass cannot produce a plan at all. Note that a REFUSED departure set is
/// not an error: the plan is still valid and its arrivals are still actionable.
pub async fn plan<S>(
    source: &S,
    inputs: &SyncInputs,
    previous: &BTreeSet<String>,
) -> Result<SyncPlan, SyncError>
where
    S: EntrySource + GroupSource + Sync,
    SyncError: From<<S as EntrySource>::Error> + From<<S as GroupSource>::Error>,
{
    // DERIVED, never hand-listed: see `attributes_to_request`.
    let attributes = attributes_to_request(&inputs.attribute_mapping);
    let entries = source
        .search(&inputs.user_base_dn, &inputs.user_filter, &attributes)
        .await?;

    let mut present = Vec::with_capacity(entries.len());
    let mut observed = BTreeSet::new();
    let mut rename_fragile = 0;
    for entry in &entries {
        let mapped = principal_for(entry, &inputs.attribute_mapping).map_err(|error| {
            SyncError::Mapping {
                dn: entry.dn.clone(),
                error,
            }
        })?;
        if !mapped.stable_id_source.survives_rename() {
            rename_fragile += 1;
        }
        // TWO ENTRIES, ONE IDENTITY is not survivable. Writing both means the second overwrites
        // the first, and the first then looks departed on the next pass -- a deprovisioning
        // caused by a directory that has two records for one person.
        if !observed.insert(mapped.stable_id.clone()) {
            let first = present
                .iter()
                .find(|p: &&MappedPrincipal| p.stable_id == mapped.stable_id)
                .map_or_else(String::new, |p| p.dn.clone());
            return Err(SyncError::DuplicateStableId {
                stable_id: mapped.stable_id,
                dns: [first, mapped.dn],
            });
        }
        present.push(mapped);
    }

    // The group walk decides who is IN SCOPE when the connector names roots. An expansion that
    // was cut short must not be read as people having left, which is what `complete` carries.
    let expansion = expand(source, &inputs.group_roots, inputs.max_group_depth).await?;

    // With no roots configured, everyone under the user base is in scope and the walk is
    // trivially whole; with roots, membership is the intersection.
    let in_scope: BTreeSet<String> = if inputs.group_roots.is_empty() {
        observed.clone()
    } else {
        // THE TWO SIDES OF THIS JOIN COME FROM DIFFERENT PLACES. `p.dn` is what the server echoed
        // on the entry; `expansion.members` holds the raw strings out of a `member` attribute.
        // A directory that writes `CN=Ada,OU=People` in one and `cn=ada,ou=People` in the other
        // is not misconfigured -- RFC 4514 leaves the case of attribute TYPES free, and most
        // servers match DNs case-insensitively. An exact-string join would drop that person from
        // scope, and a person dropped from scope reads as departed.
        //
        // Folding case is not full DN normalisation (it does not canonicalise spacing around
        // commas or unescape values), so it narrows the gap rather than closing it. The
        // alternative is a DN parser, which is a bigger dependency than this seam justifies
        // today; when one arrives, this is the site.
        let members: BTreeSet<String> = expansion
            .members
            .iter()
            .map(|dn| dn.to_ascii_lowercase())
            .collect();
        present
            .iter()
            .filter(|p| members.contains(&p.dn.to_ascii_lowercase()))
            .map(|p| p.stable_id.clone())
            .collect()
    };

    let diff = Diff::between(previous, &in_scope, expansion.complete);
    Ok(SyncPlan {
        arrivals: diff.arrivals().clone(),
        retained: diff.retained().clone(),
        departures: diff.departures().cloned(),
        present,
        rename_fragile,
        groups_complete: expansion.complete,
        groups_truncated_at: expansion.truncated_at,
    })
}

/// A source that cannot fail still has to satisfy the bound.
///
/// The test fake uses [`std::convert::Infallible`], and without this every fixture would need a
/// throwaway error type whose only job is to be converted from.
impl From<std::convert::Infallible> for SyncError {
    fn from(never: std::convert::Infallible) -> Self {
        match never {}
    }
}

impl From<DirectoryError> for SyncError {
    fn from(e: DirectoryError) -> Self {
        Self::Directory(e)
    }
}
