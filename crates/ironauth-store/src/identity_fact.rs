// SPDX-License-Identifier: MIT OR Apache-2.0

//! The identity-fact contract an external fine-grained-authorization service syncs from
//! (issue #100, criterion 5).
//!
//! # What this is, and what it deliberately is not
//!
//! Issue #100 owns the CONTRACT; the ordered events API that carries it is M11's. So this
//! module defines the fact types, their ordering key, and their translation into tuples, and
//! it defines them as a TYPE rather than as prose in a document, because a contract nothing
//! compiles against is a contract that drifts.
//!
//! It is emphatically not a `Zanzibar` engine. `IronAuth` answers what it already indexes
//! and offers seams to `OpenFGA`, `SpiceDB` or `Cerbos` for what it does not; this is the
//! seam that keeps such a service's tuples in step with the identity model, so tuple sync is
//! a CONSUMER of a declared feed rather than a scraper of the database.
//!
//! # Why a fact is not an audit row
//!
//! The audit log records what an ACTOR DID: "operator X assigned role Y". A fact records
//! what became TRUE: "membership M holds role Y". A sync consumer needs the second, and
//! deriving it from the first means reimplementing the write path's semantics in the
//! consumer, which is where a tuple store and an identity store drift apart.
//!
//! # The ordering rule, which is the whole reason this is a contract
//!
//! Facts about ONE subject must arrive in the order they became true, or a consumer that
//! sees `MembershipRemoved` before `MembershipAdded` leaves a tuple behind and grants access
//! that was revoked. Facts about DIFFERENT subjects have no relative order and must not be
//! made to wait for each other. That is exactly the transactional outbox's `ordering_group`
//! (issue #104), so [`IdentityFact::ordering_group`] is what a producer passes there, and
//! the grouping is part of this contract rather than a detail of whoever wires the feed.

use serde::{Deserialize, Serialize};

/// One fact about the identity model, in the shape a sync consumer receives it.
///
/// Additive by construction: every variant carries the ids a tuple needs and nothing else.
/// No display names, no metadata, no timestamps beyond the sequence the feed itself
/// provides. A fact that carried a display name would tempt a consumer to key on it, and a
/// rename would then look like a delete and an add.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "fact", rename_all = "snake_case")]
pub enum IdentityFact {
    /// A user exists in this environment. Emitted once per user, and again after an
    /// undelete, so a consumer that missed the original still converges.
    UserCreated {
        /// The `usr_` identifier.
        user_id: String,
    },
    /// A user was soft-deleted. A consumer removes every tuple naming the user; it must not
    /// wait for a per-membership removal, because a delete cascades in `IronAuth` and a
    /// consumer that expected N removals would hold the tuples forever if it saw N minus
    /// one.
    UserDeleted {
        /// The `usr_` identifier.
        user_id: String,
    },
    /// A user became a member of an organization.
    MembershipAdded {
        /// The `usr_` identifier.
        user_id: String,
        /// The `org_` identifier.
        organization_id: String,
        /// The `omb_` membership identifier, which is what role facts key on.
        membership_id: String,
    },
    /// A membership was removed. Its role assignments are removed WITH it and are not
    /// announced separately, for the reason [`IdentityFact::UserDeleted`] gives.
    MembershipRemoved {
        /// The `usr_` identifier.
        user_id: String,
        /// The `org_` identifier.
        organization_id: String,
        /// The `omb_` membership identifier.
        membership_id: String,
    },
    /// A role was assigned to a membership.
    RoleAssigned {
        /// The `omb_` membership identifier.
        membership_id: String,
        /// The `org_` identifier the role belongs to.
        organization_id: String,
        /// The role's immutable SLUG, not its id. A slug is what an authorization model
        /// keys on and what a `Zanzibar` relation is named after; the id is an `IronAuth`
        /// implementation detail a consumer should never have to resolve.
        role_slug: String,
    },
    /// A role was unassigned from a membership.
    RoleUnassigned {
        /// The `omb_` membership identifier.
        membership_id: String,
        /// The `org_` identifier.
        organization_id: String,
        /// The role's immutable slug.
        role_slug: String,
    },
}

impl IdentityFact {
    /// The stable wire tag, matching the `fact` discriminant serde emits.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            IdentityFact::UserCreated { .. } => "user_created",
            IdentityFact::UserDeleted { .. } => "user_deleted",
            IdentityFact::MembershipAdded { .. } => "membership_added",
            IdentityFact::MembershipRemoved { .. } => "membership_removed",
            IdentityFact::RoleAssigned { .. } => "role_assigned",
            IdentityFact::RoleUnassigned { .. } => "role_unassigned",
        }
    }

    /// The outbox ordering group this fact must be enqueued under.
    ///
    /// Every fact that can contradict another shares a group with it, and nothing else does.
    /// The grouping key is the USER for user and membership facts, and the MEMBERSHIP for
    /// role facts, which is the coarsest grouping that still serialises every pair whose
    /// order matters:
    ///
    /// * `MembershipAdded` then `MembershipRemoved` for one user must not reorder, or a
    ///   consumer keeps a tuple for an organization the user left.
    /// * `RoleAssigned` then `RoleUnassigned` for one membership must not reorder, for the
    ///   same reason one level down.
    /// * Two DIFFERENT users' facts have no relative meaning, and grouping them together
    ///   would make one slow consumer block the other for no correctness gain.
    ///
    /// A membership fact and a role fact for the same person land in different groups and
    /// may therefore be delivered out of order. That is deliberate and safe: a role fact
    /// names its `organization_id`, so a consumer that receives `RoleAssigned` before the
    /// `MembershipAdded` has everything it needs to write the tuple, and one that receives
    /// it after a `MembershipRemoved` writes a tuple the removal already deleted. The second
    /// case is why a consumer must treat `MembershipRemoved` as removing the membership's
    /// role tuples too, which this module's mapping does.
    #[must_use]
    pub fn ordering_group(&self) -> &str {
        match self {
            IdentityFact::UserCreated { user_id }
            | IdentityFact::UserDeleted { user_id }
            | IdentityFact::MembershipAdded { user_id, .. }
            | IdentityFact::MembershipRemoved { user_id, .. } => user_id,
            IdentityFact::RoleAssigned { membership_id, .. }
            | IdentityFact::RoleUnassigned { membership_id, .. } => membership_id,
        }
    }

    /// Whether this fact ADDS to the authorization graph or REMOVES from it.
    ///
    /// A consumer that gets this backwards grants access instead of revoking it, so it is a
    /// method on the fact rather than a `match` each consumer writes for itself.
    #[must_use]
    pub fn is_removal(&self) -> bool {
        matches!(
            self,
            IdentityFact::UserDeleted { .. }
                | IdentityFact::MembershipRemoved { .. }
                | IdentityFact::RoleUnassigned { .. }
        )
    }
}

/// One relationship tuple in the `OpenFGA` / `Zanzibar` shape: `user#relation@object`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tuple {
    /// The subject, as `<type>:<id>`.
    pub user: String,
    /// The relation name.
    pub relation: String,
    /// The object, as `<type>:<id>`.
    pub object: String,
}

/// What a consumer should do to its tuple store for one fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TupleChange {
    /// Write these tuples.
    Write(Vec<Tuple>),
    /// Delete these tuples.
    Delete(Vec<Tuple>),
    /// Delete every tuple naming this subject, which no finite tuple list can express.
    ///
    /// A `Zanzibar` store deletes by (user, relation, object) triple, so a cascade is a
    /// QUERY plus a delete rather than a fixed list. Modelling it as its own variant is what
    /// stops a consumer emitting a partial list and believing it is done.
    DeleteAllFor {
        /// The subject, as `<type>:<id>`.
        user: String,
    },
}

/// Translate one fact into the tuple change a consumer applies.
///
/// This lives HERE and not in the demo consumer on purpose. The mapping is part of the
/// contract: two consumers that translated differently would disagree about what `IronAuth`
/// said, and the point of a declared feed is that they cannot.
#[must_use]
pub fn to_tuple_change(fact: &IdentityFact) -> TupleChange {
    match fact {
        // A user's existence is not itself a relationship, so it writes nothing. It is still
        // a fact a consumer needs: it is what lets a sync bootstrap the subject set without
        // scraping, and what makes an undelete converge.
        IdentityFact::UserCreated { .. } => TupleChange::Write(Vec::new()),
        IdentityFact::UserDeleted { user_id } => TupleChange::DeleteAllFor {
            user: format!("user:{user_id}"),
        },
        IdentityFact::MembershipAdded {
            user_id,
            organization_id,
            ..
        } => TupleChange::Write(vec![Tuple {
            user: format!("user:{user_id}"),
            relation: "member".to_owned(),
            object: format!("organization:{organization_id}"),
        }]),
        IdentityFact::MembershipRemoved {
            user_id,
            organization_id,
            ..
        } => TupleChange::Delete(vec![Tuple {
            user: format!("user:{user_id}"),
            relation: "member".to_owned(),
            object: format!("organization:{organization_id}"),
        }]),
        // A role tuple is keyed on the MEMBERSHIP, not the user. Two users can hold the same
        // role in the same organization, and keying on the user would make one user's
        // unassignment delete the other's tuple.
        IdentityFact::RoleAssigned {
            membership_id,
            organization_id,
            role_slug,
        } => TupleChange::Write(vec![Tuple {
            user: format!("membership:{membership_id}"),
            relation: role_slug.clone(),
            object: format!("organization:{organization_id}"),
        }]),
        IdentityFact::RoleUnassigned {
            membership_id,
            organization_id,
            role_slug,
        } => TupleChange::Delete(vec![Tuple {
            user: format!("membership:{membership_id}"),
            relation: role_slug.clone(),
            object: format!("organization:{organization_id}"),
        }]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn every_variant() -> Vec<IdentityFact> {
        vec![
            IdentityFact::UserCreated {
                user_id: "usr_1".to_owned(),
            },
            IdentityFact::UserDeleted {
                user_id: "usr_1".to_owned(),
            },
            IdentityFact::MembershipAdded {
                user_id: "usr_1".to_owned(),
                organization_id: "org_1".to_owned(),
                membership_id: "omb_1".to_owned(),
            },
            IdentityFact::MembershipRemoved {
                user_id: "usr_1".to_owned(),
                organization_id: "org_1".to_owned(),
                membership_id: "omb_1".to_owned(),
            },
            IdentityFact::RoleAssigned {
                membership_id: "omb_1".to_owned(),
                organization_id: "org_1".to_owned(),
                role_slug: "editor".to_owned(),
            },
            IdentityFact::RoleUnassigned {
                membership_id: "omb_1".to_owned(),
                organization_id: "org_1".to_owned(),
                role_slug: "editor".to_owned(),
            },
        ]
    }

    /// Every fact round-trips through JSON unchanged, and the `fact` tag matches
    /// [`IdentityFact::tag`].
    ///
    /// A consumer is written against the WIRE, so a variant whose tag and whose serialized
    /// discriminant disagree is a contract that lies about itself.
    #[test]
    fn every_fact_round_trips_and_its_tag_matches_the_wire() {
        for fact in every_variant() {
            let json = serde_json::to_value(&fact).expect("serializes");
            assert_eq!(
                json.get("fact").and_then(serde_json::Value::as_str),
                Some(fact.tag()),
                "{fact:?} reports a tag its wire form does not carry"
            );
            let back: IdentityFact = serde_json::from_value(json).expect("round-trips");
            assert_eq!(back, fact, "{fact:?} did not survive the round trip");
        }
    }

    /// Every ADD has a REMOVE that maps to exactly the tuples the add wrote.
    ///
    /// This is the property a sync consumer's correctness rests on: apply an add then its
    /// remove and the tuple store is back where it started. Asserted over the pairs rather
    /// than by inspection, because an asymmetry here leaks a grant that was revoked.
    #[test]
    fn every_removal_deletes_exactly_what_its_addition_wrote() {
        let pairs = [
            (
                IdentityFact::MembershipAdded {
                    user_id: "usr_1".to_owned(),
                    organization_id: "org_1".to_owned(),
                    membership_id: "omb_1".to_owned(),
                },
                IdentityFact::MembershipRemoved {
                    user_id: "usr_1".to_owned(),
                    organization_id: "org_1".to_owned(),
                    membership_id: "omb_1".to_owned(),
                },
            ),
            (
                IdentityFact::RoleAssigned {
                    membership_id: "omb_1".to_owned(),
                    organization_id: "org_1".to_owned(),
                    role_slug: "editor".to_owned(),
                },
                IdentityFact::RoleUnassigned {
                    membership_id: "omb_1".to_owned(),
                    organization_id: "org_1".to_owned(),
                    role_slug: "editor".to_owned(),
                },
            ),
        ];
        for (add, remove) in pairs {
            let TupleChange::Write(written) = to_tuple_change(&add) else {
                panic!("{add:?} must WRITE");
            };
            let TupleChange::Delete(deleted) = to_tuple_change(&remove) else {
                panic!("{remove:?} must DELETE");
            };
            assert_eq!(
                written, deleted,
                "{remove:?} does not delete what {add:?} wrote, so revoking leaves a tuple \
                 behind and the access stays granted"
            );
        }
    }

    /// `is_removal` agrees with the tuple change, over EVERY variant.
    ///
    /// Two independent statements of the same thing, so a variant added later cannot report
    /// one and do the other.
    #[test]
    fn is_removal_agrees_with_the_tuple_change_for_every_variant() {
        for fact in every_variant() {
            let removes = match to_tuple_change(&fact) {
                TupleChange::Write(_) => false,
                TupleChange::Delete(_) | TupleChange::DeleteAllFor { .. } => true,
            };
            assert_eq!(
                removes,
                fact.is_removal(),
                "{fact:?} reports is_removal={} and its tuple change says {removes}",
                fact.is_removal()
            );
        }
    }

    /// A role tuple is keyed on the MEMBERSHIP and never on the user.
    ///
    /// Two users holding the same role in one organization is ordinary. Keying the tuple on
    /// the user would make either one's unassignment delete a tuple the other still needs,
    /// and the symptom is one person losing access when a colleague's role changes.
    #[test]
    fn a_role_tuple_is_keyed_on_the_membership_so_two_holders_do_not_collide() {
        let first = to_tuple_change(&IdentityFact::RoleAssigned {
            membership_id: "omb_1".to_owned(),
            organization_id: "org_1".to_owned(),
            role_slug: "editor".to_owned(),
        });
        let second = to_tuple_change(&IdentityFact::RoleAssigned {
            membership_id: "omb_2".to_owned(),
            organization_id: "org_1".to_owned(),
            role_slug: "editor".to_owned(),
        });
        assert_ne!(
            first, second,
            "two memberships holding the same role in the same organization produced the \
             SAME tuple, so unassigning either one revokes both"
        );
    }

    /// Facts that can contradict share an ordering group; facts that cannot do not.
    #[test]
    fn the_ordering_group_serialises_exactly_the_pairs_that_can_contradict() {
        let add = IdentityFact::MembershipAdded {
            user_id: "usr_1".to_owned(),
            organization_id: "org_1".to_owned(),
            membership_id: "omb_1".to_owned(),
        };
        let remove = IdentityFact::MembershipRemoved {
            user_id: "usr_1".to_owned(),
            organization_id: "org_2".to_owned(),
            membership_id: "omb_9".to_owned(),
        };
        assert_eq!(
            add.ordering_group(),
            remove.ordering_group(),
            "one user's membership facts must be serialised, even across organizations: \
             they are the pair whose reordering leaves a tuple behind"
        );

        let other_user = IdentityFact::MembershipAdded {
            user_id: "usr_2".to_owned(),
            organization_id: "org_1".to_owned(),
            membership_id: "omb_2".to_owned(),
        };
        assert_ne!(
            add.ordering_group(),
            other_user.ordering_group(),
            "two users' facts have no relative meaning; sharing a group makes one slow \
             consumer block the other for no correctness gain"
        );

        let role = IdentityFact::RoleAssigned {
            membership_id: "omb_1".to_owned(),
            organization_id: "org_1".to_owned(),
            role_slug: "editor".to_owned(),
        };
        let unrole = IdentityFact::RoleUnassigned {
            membership_id: "omb_1".to_owned(),
            organization_id: "org_1".to_owned(),
            role_slug: "editor".to_owned(),
        };
        assert_eq!(
            role.ordering_group(),
            unrole.ordering_group(),
            "one membership's role facts must be serialised"
        );
    }

    /// A user delete is a CASCADE and cannot be expressed as a tuple list.
    ///
    /// A consumer that received a finite delete list would apply it and believe it was done,
    /// leaving every tuple the list did not mention. The variant is what makes that
    /// unrepresentable.
    #[test]
    fn a_user_delete_is_a_cascade_and_not_a_tuple_list() {
        let change = to_tuple_change(&IdentityFact::UserDeleted {
            user_id: "usr_1".to_owned(),
        });
        assert_eq!(
            change,
            TupleChange::DeleteAllFor {
                user: "user:usr_1".to_owned()
            },
            "a delete that named specific tuples would leave every tuple it did not name"
        );
    }

    /// The committed golden fixture is exactly what this contract emits.
    ///
    /// A consumer in another language is written against the FILE, so the file is the
    /// contract and this is what stops the two diverging. Regenerate it deliberately when
    /// the contract changes, which is the point: a change that edits this file is a change
    /// somebody reviewed.
    #[test]
    fn the_committed_golden_matches_what_the_contract_emits() {
        let golden = include_str!("../../../docs/design/identity-facts.golden.json");
        let expected: serde_json::Value =
            serde_json::from_str(golden).expect("the committed golden parses");
        let actual = serde_json::json!(
            every_variant()
                .iter()
                .map(|fact| serde_json::json!({
                    "fact": serde_json::to_value(fact).expect("serializes"),
                    "ordering_group": fact.ordering_group(),
                    "is_removal": fact.is_removal(),
                }))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            actual, expected,
            "docs/design/identity-facts.golden.json is stale; a consumer written against \
             the file would now disagree with the code. Review the change and update it."
        );
    }
}
