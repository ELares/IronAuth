// SPDX-License-Identifier: MIT OR Apache-2.0

//! Running every active connector, one pass each (issue #142).

use std::collections::BTreeSet;

use ironauth_admin::ldap_groups::{GroupSource, Member};
use ironauth_admin::ldap_mapping::DirectoryEntry;
use ironauth_admin::ldap_schedule::{Scheduled, SourceFactory, sweep};
use ironauth_admin::ldap_sync::{EntrySource, SyncInputs};
use serde_json::json;

/// A directory that can be told to fail.
struct Fake {
    people: Vec<DirectoryEntry>,
    fail_read: bool,
}

impl EntrySource for Fake {
    type Error = ReadFailed;

    async fn search(
        &self,
        _base: &str,
        _filter: &str,
        _attributes: &[String],
    ) -> Result<Vec<DirectoryEntry>, ReadFailed> {
        if self.fail_read {
            return Err(ReadFailed);
        }
        Ok(self.people.clone())
    }
}

impl GroupSource for Fake {
    type Error = ReadFailed;

    async fn direct_members(&self, _group_dn: &str) -> Result<Vec<Member>, ReadFailed> {
        Ok(Vec::new())
    }
}

/// A read failure that the sync can carry.
#[derive(Debug)]
struct ReadFailed;

impl std::fmt::Display for ReadFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the directory stopped answering")
    }
}

impl From<ReadFailed> for ironauth_admin::ldap_sync::SyncError {
    fn from(e: ReadFailed) -> Self {
        Self::Directory(
            ironauth_admin::ldap_client::DirectoryError::UnsupportedScheme { url: e.to_string() },
        )
    }
}

/// Opens whichever fake the connector id names, and refuses one id outright.
struct Factory {
    unopenable: BTreeSet<String>,
    failing_read: BTreeSet<String>,
}

impl SourceFactory for Factory {
    type Source = Fake;
    type Error = String;

    async fn open(&self, scheduled: &Scheduled) -> Result<Fake, String> {
        if self.unopenable.contains(&scheduled.id) {
            return Err(format!("bind refused for {}", scheduled.id));
        }
        Ok(Fake {
            people: vec![person(&format!("{}-user", scheduled.id))],
            fail_read: self.failing_read.contains(&scheduled.id),
        })
    }
}

fn person(login: &str) -> DirectoryEntry {
    DirectoryEntry::new(
        format!("uid={login},ou=People,dc=example,dc=test"),
        vec![
            ("uid".to_owned(), vec![login.to_owned()]),
            ("entryUUID".to_owned(), vec![format!("u-{login}")]),
        ],
    )
}

fn scheduled(id: &str) -> Scheduled {
    Scheduled {
        id: id.to_owned(),
        inputs: SyncInputs {
            user_base_dn: "ou=People,dc=example,dc=test".to_owned(),
            user_filter: "(objectClass=inetOrgPerson)".to_owned(),
            group_roots: Vec::new(),
            max_group_depth: 5,
            attribute_mapping: json!({ "username": "uid" }),
        },
        previous: BTreeSet::new(),
    }
}

fn factory(unopenable: &[&str], failing_read: &[&str]) -> Factory {
    Factory {
        unopenable: unopenable.iter().map(|s| (*s).to_owned()).collect(),
        failing_read: failing_read.iter().map(|s| (*s).to_owned()).collect(),
    }
}

/// THE ISOLATION PROPERTY. One connector refusing its bind does not stop the others.
#[tokio::test]
async fn a_connector_that_cannot_be_opened_does_not_stop_the_sweep() {
    let all = [scheduled("alpha"), scheduled("broken"), scheduled("gamma")];
    let report = sweep(&factory(&["broken"], &[]), &all).await;

    assert_eq!(
        report.runs.len(),
        3,
        "every scheduled connector is reported"
    );
    assert!(report.runs[0].1.is_planned(), "alpha ran");
    assert!(report.runs[2].1.is_planned(), "gamma ran after the failure");
    assert_eq!(
        report.failures(),
        vec![("broken", "bind refused for broken")]
    );
    assert!(!report.every_connector_planned());
}

/// A connector that opens and then fails MID-READ is isolated too, and is reported differently.
///
/// The distinction matters to whoever reads the report first: a refused bind is a credential or
/// network fact, a failed read is a directory-shape fact, and they send an operator to different
/// places.
#[tokio::test]
async fn a_read_that_fails_after_a_successful_bind_is_reported_as_a_failure_not_unreachable() {
    let all = [scheduled("alpha"), scheduled("flaky")];
    let report = sweep(&factory(&[], &["flaky"]), &all).await;

    assert!(report.runs[0].1.is_planned());
    let (id, why) = report.failures()[0];
    assert_eq!(id, "flaky");
    assert!(
        why.contains("stopped answering"),
        "the reason must carry the read failure, not a generic message: {why}"
    );
    assert!(
        matches!(
            report.runs[1].1,
            ironauth_admin::ldap_schedule::Outcome::Failed(_)
        ),
        "a post-bind failure is Failed, not Unreachable"
    );
}

/// A FAILED CONNECTOR IS IN THE REPORT, not missing from it.
///
/// The tempting shape is a list of whatever worked. A failed connector absent from the report is
/// indistinguishable from one with nothing to do -- and the thing downstream is deprovisioning,
/// so "nothing to do" and "could not look" must never render the same.
#[tokio::test]
async fn every_scheduled_connector_appears_in_the_report_even_when_all_of_them_fail() {
    let all = [scheduled("one"), scheduled("two")];
    let report = sweep(&factory(&["one", "two"], &[]), &all).await;

    assert_eq!(report.runs.len(), 2);
    assert_eq!(report.failures().len(), 2);
    assert!(!report.every_connector_planned());
    assert!(
        report.runs.iter().all(|(_, o)| !o.is_planned()),
        "nothing was planned, and the report says so per connector"
    );
}

/// An all-healthy sweep says so, and the ids come back in the order they were scheduled.
#[tokio::test]
async fn a_healthy_sweep_plans_every_connector_in_order() {
    let all = [scheduled("alpha"), scheduled("beta"), scheduled("gamma")];
    let report = sweep(&factory(&[], &[]), &all).await;

    assert!(report.every_connector_planned());
    assert!(report.failures().is_empty());
    let ids: Vec<&str> = report.runs.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(ids, ["alpha", "beta", "gamma"]);
}

/// An empty schedule is an empty report, not a failure.
#[tokio::test]
async fn a_sweep_with_nothing_scheduled_reports_nothing_and_succeeds() {
    let report = sweep(&factory(&[], &[]), &[]).await;
    assert!(report.runs.is_empty());
    assert!(
        report.every_connector_planned(),
        "vacuously true, and it must not be reported as a failure"
    );
}
