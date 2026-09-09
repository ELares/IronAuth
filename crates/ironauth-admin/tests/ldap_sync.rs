// SPDX-License-Identifier: MIT OR Apache-2.0

//! One pass of a directory sync (issue #142).

use std::collections::{BTreeMap, BTreeSet};

use ironauth_admin::ldap_diff::DepartureRefusal;
use ironauth_admin::ldap_groups::{GroupSource, Member};
use ironauth_admin::ldap_mapping::DirectoryEntry;
use ironauth_admin::ldap_sync::{EntrySource, SyncError, SyncInputs, plan};
use serde_json::json;

/// A directory with a fixed set of people and a fixed group graph.
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

fn person(login: &str, stable: Option<&str>) -> DirectoryEntry {
    let dn = format!("uid={login},ou=People,dc=example,dc=test");
    let mut attrs = vec![
        ("uid".to_owned(), vec![login.to_owned()]),
        ("cn".to_owned(), vec![login.to_owned()]),
    ];
    if let Some(id) = stable {
        attrs.push(("entryUUID".to_owned(), vec![id.to_owned()]));
    }
    DirectoryEntry::new(dn, attrs)
}

fn inputs(roots: &[&str], depth: u32) -> SyncInputs {
    SyncInputs {
        user_base_dn: "ou=People,dc=example,dc=test".to_owned(),
        user_filter: "(objectClass=inetOrgPerson)".to_owned(),
        group_roots: roots.iter().map(|r| (*r).to_owned()).collect(),
        max_group_depth: depth,
        attribute_mapping: json!({ "username": "uid", "display_name": "cn" }),
    }
}

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

/// With no group roots configured, everyone under the user base is in scope.
#[tokio::test]
async fn a_pass_with_no_group_roots_takes_everyone_under_the_base() {
    let fake = Fake {
        people: vec![
            person("ada", Some("u-ada")),
            person("grace", Some("u-grace")),
        ],
        groups: BTreeMap::new(),
    };
    let out = plan(&fake, &inputs(&[], 5), &set(&["u-ada"]))
        .await
        .expect("plans");

    assert_eq!(out.arrivals, set(&["u-grace"]));
    assert_eq!(out.retained, set(&["u-ada"]));
    assert!(out.departures.expect("complete").is_empty());
    assert_eq!(out.present.len(), 2);
    assert_eq!(out.rename_fragile, 0);
    assert!(out.groups_complete);
}

/// With roots configured, scope is the intersection: a person outside the group is not in it.
#[tokio::test]
async fn group_roots_narrow_the_scope_to_their_members() {
    let mut groups = BTreeMap::new();
    groups.insert(
        "cn=eng,ou=Groups,dc=example,dc=test".to_owned(),
        vec![Member {
            dn: "uid=ada,ou=People,dc=example,dc=test".to_owned(),
            is_group: false,
        }],
    );
    let fake = Fake {
        people: vec![
            person("ada", Some("u-ada")),
            person("outsider", Some("u-out")),
        ],
        groups,
    };

    let out = plan(
        &fake,
        &inputs(&["cn=eng,ou=Groups,dc=example,dc=test"], 5),
        &BTreeSet::new(),
    )
    .await
    .expect("plans");

    assert_eq!(
        out.arrivals,
        set(&["u-ada"]),
        "only the group member is in scope"
    );
    assert_eq!(
        out.present.len(),
        2,
        "both people were READ; scope is about membership, not about what the search returned"
    );
}

/// THE PROPERTY THE WHOLE CHAIN EXISTS FOR: a truncated group walk refuses departures.
///
/// This is the end-to-end version of what `ldap_diff` pins in isolation. Here the incompleteness
/// originates in a real expansion, travels through the plan, and lands on the caller as a
/// refusal -- which is the wiring that did not exist while these were four separate modules.
#[tokio::test]
async fn a_truncated_group_walk_refuses_departures_but_still_offers_arrivals() {
    let mut groups = BTreeMap::new();
    groups.insert(
        "cn=all,ou=Groups,dc=example,dc=test".to_owned(),
        vec![
            Member {
                dn: "uid=ada,ou=People,dc=example,dc=test".to_owned(),
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
        people: vec![
            person("ada", Some("u-ada")),
            person("hidden", Some("u-hid")),
        ],
        groups,
    };

    // depth 0: `nested` is never descended into, so `hidden` is missing from the member set.
    let out = plan(
        &fake,
        &inputs(&["cn=all,ou=Groups,dc=example,dc=test"], 0),
        &set(&["u-ada", "u-hid"]),
    )
    .await
    .expect("plans");

    assert!(!out.groups_complete);
    assert!(
        out.groups_truncated_at
            .contains("cn=nested,ou=Groups,dc=example,dc=test")
    );
    assert_eq!(
        out.departures
            .expect_err("a cut walk cannot name departures"),
        DepartureRefusal::ObservationIncomplete
    );
    // AND THE CONTRAST: the same directory fully walked names nobody as departed.
    let whole = plan(
        &fake,
        &inputs(&["cn=all,ou=Groups,dc=example,dc=test"], 5),
        &set(&["u-ada", "u-hid"]),
    )
    .await
    .expect("plans");
    assert!(whole.groups_complete);
    assert!(
        whole.departures.expect("complete").is_empty(),
        "nobody left; the bound merely hid one of them"
    );
}

/// Two entries claiming one identity aborts the pass.
///
/// Writing both means the second overwrites the first, and the first then looks departed on the
/// next pass -- a deprovisioning caused by a directory holding two records for one person.
#[tokio::test]
async fn two_entries_with_the_same_stable_id_abort_the_pass() {
    let fake = Fake {
        people: vec![person("ada", Some("same")), person("ada2", Some("same"))],
        groups: BTreeMap::new(),
    };
    let err = plan(&fake, &inputs(&[], 5), &BTreeSet::new())
        .await
        .expect_err("must refuse");
    match err {
        SyncError::DuplicateStableId { stable_id, dns } => {
            assert_eq!(stable_id, "same");
            assert!(dns[0].contains("uid=ada,"), "{dns:?}");
            assert!(dns[1].contains("uid=ada2,"), "{dns:?}");
        }
        other => panic!("wrong error: {other:?}"),
    }
}

/// An unmappable entry aborts the pass rather than being skipped.
///
/// Skipping would shrink the member set, and the diff reads a shrunken set as departures -- so
/// "just skip the bad row" would deprovision people because of a configuration typo.
#[tokio::test]
async fn an_unmappable_entry_aborts_rather_than_shrinking_the_member_set() {
    // No `uid`, and the mapping's username source is `uid`.
    let nameless = DirectoryEntry::new(
        "cn=nameless,ou=People,dc=example,dc=test",
        vec![("cn".to_owned(), vec!["Nameless".to_owned()])],
    );
    let fake = Fake {
        people: vec![person("ada", Some("u-ada")), nameless],
        groups: BTreeMap::new(),
    };
    let err = plan(&fake, &inputs(&[], 5), &set(&["u-ada"]))
        .await
        .expect_err("must refuse");
    assert!(
        matches!(err, SyncError::Mapping { ref dn, .. } if dn.contains("nameless")),
        "wrong error: {err:?}"
    );
}

/// A directory with no rename-stable handle is counted, not hidden.
#[tokio::test]
async fn principals_identified_only_by_their_dn_are_counted_as_rename_fragile() {
    let fake = Fake {
        people: vec![person("ada", None), person("grace", Some("u-grace"))],
        groups: BTreeMap::new(),
    };
    let out = plan(&fake, &inputs(&[], 5), &BTreeSet::new())
        .await
        .expect("plans");
    assert_eq!(
        out.rename_fragile, 1,
        "exactly one entry has no UUID and falls back to its DN"
    );
    assert_eq!(out.present.len(), 2);
}
