// SPDX-License-Identifier: MIT OR Apache-2.0

//! Translating a plan and a policy into the exact operations a run would perform (issue #142).

use std::collections::{BTreeMap, BTreeSet};

use ironauth_admin::ldap_changeset::{Change, ChangeSet};
use ironauth_admin::ldap_diff::DepartureRefusal;
use ironauth_admin::ldap_groups::{GroupSource, Member};
use ironauth_admin::ldap_mapping::DirectoryEntry;
use ironauth_admin::ldap_sync::{EntrySource, SyncInputs, SyncPlan, plan};
use ironauth_store::LdapAbsencePolicy;
use serde_json::json;

struct Fake {
    people: Vec<DirectoryEntry>,
    groups: BTreeMap<String, Vec<Member>>,
}

impl EntrySource for Fake {
    type Error = std::convert::Infallible;
    async fn search(
        &self,
        _base: &str,
        _filter: &str,
        _attributes: &[String],
    ) -> Result<Vec<DirectoryEntry>, Self::Error> {
        Ok(self.people.clone())
    }
}

impl GroupSource for Fake {
    type Error = std::convert::Infallible;
    async fn direct_members(&self, group_dn: &str) -> Result<Vec<Member>, Self::Error> {
        Ok(self.groups.get(group_dn).cloned().unwrap_or_default())
    }
}

fn person(login: &str, stable: &str) -> DirectoryEntry {
    DirectoryEntry::new(
        format!("uid={login},ou=People,dc=example,dc=test"),
        vec![
            ("uid".to_owned(), vec![login.to_owned()]),
            ("entryUUID".to_owned(), vec![stable.to_owned()]),
        ],
    )
}

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

async fn planned(people: &[(&str, &str)], previous: &[&str]) -> SyncPlan {
    let fake = Fake {
        people: people.iter().map(|(l, s)| person(l, s)).collect(),
        groups: BTreeMap::new(),
    };
    plan(
        &fake,
        &SyncInputs {
            user_base_dn: "ou=People,dc=example,dc=test".to_owned(),
            user_filter: "(objectClass=inetOrgPerson)".to_owned(),
            group_roots: Vec::new(),
            max_group_depth: 5,
            attribute_mapping: json!({ "username": "uid" }),
        },
        &set(previous),
    )
    .await
    .expect("plans")
}

/// POLICY TRANSLATION, the verification bullet #142 names: deactivate versus delete.
#[tokio::test]
async fn the_policy_decides_which_removal_a_departure_becomes() {
    let p = planned(&[("stays", "u-stays")], &["u-stays", "u-gone"]).await;

    let keeping = ChangeSet::from_plan(&p, LdapAbsencePolicy::Deactivate);
    assert_eq!(
        keeping.changes,
        vec![Change::Deactivate {
            stable_id: "u-gone".to_owned()
        }]
    );
    assert!(
        !keeping.deletes_anybody(),
        "the reversible policy must not report an irreversible run"
    );

    let removing = ChangeSet::from_plan(&p, LdapAbsencePolicy::Delete);
    assert_eq!(
        removing.changes,
        vec![Change::Delete {
            stable_id: "u-gone".to_owned()
        }]
    );
    assert!(removing.deletes_anybody());

    // The SAME departure under both policies, so the two above differ only by the policy and
    // not by the plan they were built from.
    assert_eq!(keeping.removals(), removing.removals());
}

/// PROVISIONS COME FIRST.
///
/// Somebody who moved between two synced groups can present as one departure and one arrival for
/// the same human. Doing the arrival first makes the window where they cannot sign in zero rather
/// than however long the removals take.
#[tokio::test]
async fn arrivals_are_ordered_before_removals() {
    let p = planned(&[("newcomer", "u-new")], &["u-old"]).await;
    let set = ChangeSet::from_plan(&p, LdapAbsencePolicy::Deactivate);

    assert_eq!(
        set.changes,
        vec![
            Change::Provision {
                stable_id: "u-new".to_owned(),
                username: "newcomer".to_owned(),
            },
            Change::Deactivate {
                stable_id: "u-old".to_owned(),
            },
        ],
        "a provision must precede every removal"
    );
}

/// A REFUSED DEPARTURE SET PRODUCES NO REMOVALS, AND SAYS WHY.
///
/// The alternative -- an empty removal list with no explanation -- reads as "nobody left", which
/// is the one thing a truncated read must never be mistaken for. The arrivals are still there,
/// because a short read can only under-report an arrival.
#[tokio::test]
async fn a_withheld_departure_set_carries_its_reason_rather_than_showing_nothing() {
    let mut groups = BTreeMap::new();
    groups.insert(
        "cn=all,ou=Groups,dc=example,dc=test".to_owned(),
        vec![
            Member {
                dn: "uid=stays,ou=People,dc=example,dc=test".to_owned(),
                is_group: false,
            },
            Member {
                dn: "cn=nested,ou=Groups,dc=example,dc=test".to_owned(),
                is_group: true,
            },
        ],
    );
    groups.insert(
        "cn=nested,ou=Groups,dc=example,dc=test".to_owned(),
        vec![Member {
            dn: "uid=hidden,ou=People,dc=example,dc=test".to_owned(),
            is_group: false,
        }],
    );
    let fake = Fake {
        people: vec![person("stays", "u-stays"), person("hidden", "u-hidden")],
        groups,
    };
    let truncated = plan(
        &fake,
        &SyncInputs {
            user_base_dn: "ou=People,dc=example,dc=test".to_owned(),
            user_filter: "(objectClass=inetOrgPerson)".to_owned(),
            group_roots: vec!["cn=all,ou=Groups,dc=example,dc=test".to_owned()],
            max_group_depth: 0,
            attribute_mapping: json!({ "username": "uid" }),
        },
        &set(&["u-stays", "u-hidden"]),
    )
    .await
    .expect("plans");

    let changes = ChangeSet::from_plan(&truncated, LdapAbsencePolicy::Delete);
    assert!(
        changes.removals().is_empty(),
        "a refused departure set must produce no removals: {:?}",
        changes.changes
    );
    assert_eq!(
        changes.withheld,
        Some(DepartureRefusal::ObservationIncomplete),
        "and the reason must travel with the change set, or an operator reads it as nobody left"
    );
    assert!(!changes.deletes_anybody());
}

/// An unchanged directory produces an empty change set with nothing withheld.
///
/// Both halves matter: `withheld: None` on a quiet run is what distinguishes it from a refused
/// one, and without this assertion `withheld` could be `Some` always and no test would notice.
#[tokio::test]
async fn a_quiet_run_is_empty_and_withholds_nothing() {
    let p = planned(&[("ada", "u-ada")], &["u-ada"]).await;
    let changes = ChangeSet::from_plan(&p, LdapAbsencePolicy::Delete);
    assert!(changes.is_empty());
    assert_eq!(changes.withheld, None);
}

/// A provision carries the login the mapper resolved, not the identifier.
///
/// The stable id is a UUID; a record created under it would be a person nobody can find. The
/// username comes from the plan's `present` list, keyed by stable id.
#[tokio::test]
async fn a_provision_carries_the_resolved_login() {
    let p = planned(&[("ada.lovelace", "u-ada")], &[]).await;
    let changes = ChangeSet::from_plan(&p, LdapAbsencePolicy::Deactivate);
    assert_eq!(
        changes.changes,
        vec![Change::Provision {
            stable_id: "u-ada".to_owned(),
            username: "ada.lovelace".to_owned(),
        }]
    );
    assert_eq!(changes.provisions(), ["u-ada"].into_iter().collect());
}

/// THE OTHER REFUSAL, and its payload, travelling through the change set.
///
/// The suite only ever produced `ObservationIncomplete`, so the assertion that "the reason must
/// travel" compared the one value the fixtures could generate: hardcoding
/// `Some(ObservationIncomplete)` in place of the plan's reason passed everything.
///
/// The two refusals demand opposite responses. `ObservationIncomplete` means retry with a bigger
/// bound. `EverybodyVanished` means STOP: the read succeeded and returned nobody, which is a base
/// DN typo or a revoked read grant, and its `previously` count is how an operator sizes what was
/// about to happen. Collapsing one into the other tells them to retry the thing they must not.
#[tokio::test]
async fn the_everybody_vanished_refusal_reaches_the_change_set_with_its_count() {
    let p = planned(&[], &["u-a", "u-b", "u-c"]).await;
    let changes = ChangeSet::from_plan(&p, LdapAbsencePolicy::Delete);

    assert_eq!(
        changes.withheld,
        Some(DepartureRefusal::EverybodyVanished { previously: 3 }),
        "the reason AND its count must be the plan's, not a constant"
    );
    assert!(
        changes.removals().is_empty(),
        "a read that returned nobody must remove nobody"
    );
    assert!(!changes.deletes_anybody());
}

/// `removals()` REPORTS THE REMOVALS, which nothing pinned.
///
/// It was queried twice: once for emptiness, once in an equality whose two sides come from the
/// same function on the same plan. So `removals()` returning an empty set for every input passed
/// -- and that made the refusal test's safety assertion vacuous, because the accessor it
/// interrogates would answer "empty" while the change set carried removals an executor would run.
/// Reporting provisions AS removals passed too, which is the list a confirmation prompt shows.
#[tokio::test]
async fn removals_names_exactly_the_people_being_removed() {
    let p = planned(&[("newcomer", "u-new")], &["u-old"]).await;
    let changes = ChangeSet::from_plan(&p, LdapAbsencePolicy::Deactivate);

    assert_eq!(
        changes.removals(),
        ["u-old"].into_iter().collect(),
        "removals must be the departures and nothing else"
    );
    assert_eq!(
        changes.provisions(),
        ["u-new"].into_iter().collect(),
        "and the arrival must not appear among them"
    );
    // The two sets are disjoint, which is the property a confirmation prompt depends on: an
    // operator told "these will be removed" must not be reading the list of people who joined.
    assert!(
        changes
            .removals()
            .intersection(&changes.provisions())
            .next()
            .is_none()
    );
}
