// SPDX-License-Identifier: MIT OR Apache-2.0

//! Deletion propagation across two passes (issue #142), over a real database and no directory.
//!
//! This is the acceptance criterion: "a user deleted from the directory is deactivated/deleted in
//! IronAuth on the next scheduled sync, and the deprovisioning cascade fires". It needs TWO
//! passes and the snapshot between them, because one pass can never detect an absence -- there is
//! nothing to be absent from.
//!
//! The loop here is the one [`run_pass`](ironauth_admin::ldap_boot::run_pass) runs: read every
//! snapshot in the scope, sweep each connector against its own, apply, record. Only the opening
//! of directory connections is left out, and that is the part a live server owns.

#![cfg(feature = "testing")]

use std::collections::{BTreeMap, BTreeSet};

use ironauth_admin::ldap_boot::{
    ApplyTerms, PassReport, ScopeSweep, apply_sweep, fold_scope, previous_for, reconciled,
};
use ironauth_admin::ldap_changeset::ChangeSet;
use ironauth_admin::ldap_groups::{GroupSource, Member};
use ironauth_admin::ldap_mapping::DirectoryEntry;
use ironauth_admin::ldap_schedule::{Outcome, SweepReport};
use ironauth_admin::ldap_sync::{EntrySource, SyncInputs, SyncPlan, plan};
use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ActorRef, CorrelationId, LdapAbsencePolicy, LdapConnector, LdapConnectorId, LdapTlsMode,
    NewLdapConnector, OrganizationId, Scope, ServiceId, Store, UserState,
};
use serde_json::json;

struct Fake {
    people: Vec<DirectoryEntry>,
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
    async fn direct_members(&self, _group_dn: &str) -> Result<Vec<Member>, Self::Error> {
        Ok(Vec::new())
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

/// A plan for a directory holding exactly `people`, diffed against `previous`.
async fn planned(people: &[(&str, &str)], previous: &BTreeSet<String>) -> SyncPlan {
    let fake = Fake {
        people: people.iter().map(|(l, s)| person(l, s)).collect(),
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
        previous,
    )
    .await
    .expect("plans")
}

fn now(env: &Env) -> i64 {
    i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after the epoch")
            .as_micros(),
    )
    .expect("in range")
}

async fn seed_connector(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    policy: LdapAbsencePolicy,
) -> LdapConnectorId {
    let org = OrganizationId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .organizations(scope)
        .create(env, &org, now(env), "Directory Co", None)
        .await
        .expect("create organization");
    let id = LdapConnectorId::generate(env, &scope);
    let mapping = json!({ "username": "uid" });
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .ldap_connectors()
        .create(
            env,
            NewLdapConnector {
                id: &id,
                organization_id: &org,
                display_name: "Contoso AD",
                host: "ad.contoso.test",
                port: 636,
                tls_mode: LdapTlsMode::Ldaps,
                bind_dn: "cn=svc,dc=contoso,dc=test",
                bind_secret_name: "contoso-bind",
                user_base_dn: "ou=People,dc=example,dc=test",
                group_base_dn: "",
                user_filter: "(objectClass=inetOrgPerson)",
                group_filter: "",
                attribute_mapping: &mapping,
                absence_policy: policy,
                max_group_depth: 5,
            },
        )
        .await
        .expect("create connector");
    id
}

fn terms(connector: &LdapConnectorId, policy: LdapAbsencePolicy) -> ApplyTerms {
    ApplyTerms {
        policy,
        actor: ActorRef::service(ServiceId::from_seed_bytes(connector.unique_bytes())),
    }
}

fn sweep_of(connector: &LdapConnectorId, plan: SyncPlan, terms: ApplyTerms) -> ScopeSweep {
    ScopeSweep {
        report: SweepReport {
            runs: vec![(connector.to_string(), Outcome::Planned(Box::new(plan)))],
        },
        terms: BTreeMap::from([(connector.to_string(), terms)]),
    }
}

async fn state_of(store: &Store, scope: Scope, stable: &str) -> Option<UserState> {
    store
        .scoped(scope)
        .users()
        .by_external_id(stable)
        .await
        .expect("read by external id")
        .map(|record| record.state)
}

async fn snapshot_of(
    store: &Store,
    scope: Scope,
    connector: &LdapConnectorId,
) -> Option<BTreeSet<String>> {
    store
        .scoped(scope)
        .ldap_sync_snapshots()
        .get(connector)
        .await
        .expect("read the snapshot")
}

/// One pass, exactly as `run_pass` runs it: read the snapshot, diff against it, apply, record.
async fn one_pass(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    connector: &LdapConnectorId,
    directory: &[(&str, &str)],
    policy: LdapAbsencePolicy,
) -> PassReport {
    let store = db.control_store();
    let previous = store
        .scoped(scope)
        .ldap_sync_snapshots()
        .all_in_scope()
        .await
        .expect("read every snapshot");
    let row = store
        .scoped(scope)
        .ldap_connectors()
        .get(connector)
        .await
        .expect("read the connector");
    let plan = planned(directory, &previous_for(&previous, &row)).await;
    let mut report = PassReport::default();
    fold_scope(
        store,
        scope,
        env,
        &db.master_key(),
        &sweep_of(connector, plan, terms(connector, policy)),
        &mut report,
    )
    .await;
    report
}

/// THE CRITERION. Somebody in the directory on Monday and gone on Tuesday is disabled on
/// Tuesday's pass -- which takes two passes and the snapshot between them, and was impossible
/// before this table existed.
#[tokio::test]
async fn a_principal_who_leaves_the_directory_is_disabled_on_the_next_pass() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.control_store();
    let soft = LdapAbsencePolicy::Deactivate;
    let connector = seed_connector(&db, &env, scope, soft).await;

    let monday = one_pass(
        &db,
        &env,
        scope,
        &connector,
        &[("ada", "u-ada"), ("grace", "u-grace")],
        soft,
    )
    .await;
    assert_eq!(monday.applied.provisioned, 2, "{monday:?}");
    assert_eq!(
        monday.applied.deactivated, 0,
        "a FIRST pass has nothing to be absent from and must remove nobody"
    );
    assert_eq!(monday.snapshots_recorded, 1);
    assert_eq!(
        snapshot_of(store, scope, &connector).await,
        Some(BTreeSet::from(["u-ada".to_owned(), "u-grace".to_owned()])),
        "the pass did not record what it saw"
    );

    let tuesday = one_pass(&db, &env, scope, &connector, &[("ada", "u-ada")], soft).await;

    assert_eq!(
        tuesday.applied.deactivated, 1,
        "the departed principal was not deprovisioned: {tuesday:?}"
    );
    assert!(
        tuesday.applied.everything_applied(),
        "{:?}",
        tuesday.applied.failures
    );
    assert_eq!(
        state_of(store, scope, "u-grace").await,
        Some(UserState::Disabled),
        "somebody removed from the directory still has a live account"
    );
    assert_eq!(
        state_of(store, scope, "u-ada").await,
        Some(UserState::Active),
        "somebody still in the directory was deprovisioned"
    );
    assert_eq!(
        snapshot_of(store, scope, &connector).await,
        Some(BTreeSet::from(["u-ada".to_owned()])),
        "the second pass did not narrow the snapshot"
    );

    // And Wednesday, unchanged: the repeat must be quiet, not a second removal or a failure.
    let wednesday = one_pass(&db, &env, scope, &connector, &[("ada", "u-ada")], soft).await;
    assert_eq!(wednesday.applied.deactivated, 0);
    assert!(
        wednesday.applied.everything_applied(),
        "{:?}",
        wednesday.applied.failures
    );
}

/// THE SAME UNDER THE IRREVERSIBLE POLICY, because the two removals reach different store calls.
#[tokio::test]
async fn a_delete_policy_connector_removes_the_account_on_the_next_pass() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.control_store();
    let hard = LdapAbsencePolicy::Delete;
    let connector = seed_connector(&db, &env, scope, hard).await;

    one_pass(
        &db,
        &env,
        scope,
        &connector,
        &[("stay", "u-stay"), ("go", "u-go")],
        hard,
    )
    .await;
    let second = one_pass(&db, &env, scope, &connector, &[("stay", "u-stay")], hard).await;

    assert_eq!(second.applied.deleted, 1, "{second:?}");
    assert_eq!(state_of(store, scope, "u-go").await, None);
    assert_eq!(
        state_of(store, scope, "u-stay").await,
        Some(UserState::Active)
    );
}

/// AN EMPTIED DIRECTORY RECORDS NOTHING, so the snapshot from the pass before it survives. Were
/// the emptied read recorded, the next pass -- reading the directory correctly again -- would
/// compare against nobody and conclude that nobody had ever left.
#[tokio::test]
async fn a_refused_observation_leaves_the_previous_snapshot_standing() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.control_store();
    let soft = LdapAbsencePolicy::Deactivate;
    let connector = seed_connector(&db, &env, scope, soft).await;

    one_pass(
        &db,
        &env,
        scope,
        &connector,
        &[("a", "u-a"), ("b", "u-b")],
        soft,
    )
    .await;
    let good = snapshot_of(store, scope, &connector).await;
    assert_eq!(
        good,
        Some(BTreeSet::from(["u-a".to_owned(), "u-b".to_owned()]))
    );

    // The directory answers with nobody: the shape of a failure, not of everybody resigning.
    let blank = one_pass(&db, &env, scope, &connector, &[], soft).await;

    assert_eq!(blank.refusing_departures, 1, "{blank:?}");
    assert_eq!(blank.applied.deactivated, 0, "an empty read deprovisioned");
    assert_eq!(
        blank.snapshots_recorded, 0,
        "a refused observation was recorded as the new truth"
    );
    assert_eq!(
        snapshot_of(store, scope, &connector).await,
        good,
        "the refused pass overwrote a good snapshot"
    );
    assert_eq!(state_of(store, scope, "u-a").await, Some(UserState::Active));

    // The directory recovers, minus one person: the departure is still detectable.
    let recovered = one_pass(&db, &env, scope, &connector, &[("a", "u-a")], soft).await;
    assert_eq!(
        recovered.applied.deactivated, 1,
        "the outage lost the evidence that u-b had left: {recovered:?}"
    );
    assert_eq!(
        state_of(store, scope, "u-b").await,
        Some(UserState::Disabled)
    );
}

/// A FAILED REMOVAL STAYS IN THE SNAPSHOT, so the next pass tries again. Recording the failure as
/// though it had succeeded is the forever-alive account, arrived at by a different road.
#[tokio::test]
async fn a_removal_that_failed_is_retried_on_the_next_pass() {
    let leaving = planned(
        &[("stay", "u-stay")],
        &BTreeSet::from(["u-stay".to_owned(), "u-gone".to_owned()]),
    )
    .await;
    let changes = ChangeSet::from_plan(&leaving, LdapAbsencePolicy::Deactivate);
    let mut failed = ironauth_admin::ldap_execute::ExecuteReport::default();
    failed
        .failures
        .push(("u-gone".to_owned(), "the database said no".to_owned()));

    let recorded = reconciled(&leaving, &changes, &failed).expect("a complete observation");
    assert!(
        recorded.contains("u-gone"),
        "a removal that failed was recorded as done, so it will never be retried: {recorded:?}"
    );
    assert!(recorded.contains("u-stay"));
}

/// AND A FAILED PROVISION IS DROPPED, so the next pass sees them as an arrival again. Recording
/// them would mean the retry never happens and they never get an account at all.
#[tokio::test]
async fn a_provision_that_failed_is_retried_on_the_next_pass() {
    let arriving = planned(&[("one", "u-one"), ("two", "u-two")], &BTreeSet::new()).await;
    let changes = ChangeSet::from_plan(&arriving, LdapAbsencePolicy::Deactivate);
    let mut failed = ironauth_admin::ldap_execute::ExecuteReport::default();
    failed
        .failures
        .push(("u-two".to_owned(), "duplicate login".to_owned()));

    let recorded = reconciled(&arriving, &changes, &failed).expect("a complete observation");
    assert_eq!(
        recorded,
        BTreeSet::from(["u-one".to_owned()]),
        "a provision that failed was recorded as present, so it will never be retried"
    );
}

/// THE LOOKUP KEY. A `previous_for` that missed would hand every connector an empty set and
/// disable absence detection everywhere, silently, while every test about the diff went on
/// passing.
#[tokio::test]
async fn the_previous_set_is_looked_up_by_connector_id() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let mine = seed_connector(&db, &env, scope, LdapAbsencePolicy::Deactivate).await;
    let other = seed_connector(&db, &env, scope, LdapAbsencePolicy::Deactivate).await;

    let store = db.control_store();
    store
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .ldap_sync_snapshots()
        .record(
            &env,
            &db.master_key(),
            &mine,
            &BTreeSet::from(["u-mine".to_owned()]),
            now(&env),
        )
        .await
        .expect("record");

    let all = store
        .scoped(scope)
        .ldap_sync_snapshots()
        .all_in_scope()
        .await
        .expect("read");
    let mine_row: LdapConnector = store
        .scoped(scope)
        .ldap_connectors()
        .get(&mine)
        .await
        .expect("read mine");
    let other_row: LdapConnector = store
        .scoped(scope)
        .ldap_connectors()
        .get(&other)
        .await
        .expect("read other");

    assert_eq!(
        previous_for(&all, &mine_row),
        BTreeSet::from(["u-mine".to_owned()]),
        "the connector's own snapshot was not found"
    );
    assert_eq!(
        previous_for(&all, &other_row),
        BTreeSet::new(),
        "a connector with no snapshot was handed somebody else's"
    );
}

/// A CONNECTOR WITH NO POLICY RECORDS NOTHING EITHER. Nothing was applied for it, so recording
/// what its directory held would tell the next pass that IronAuth had agreed with a read it never
/// acted on -- and everybody in it would be silently forgotten.
#[tokio::test]
async fn a_plan_whose_policy_is_missing_records_no_snapshot() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.control_store();
    let connector = seed_connector(&db, &env, scope, LdapAbsencePolicy::Deactivate).await;

    let orphan = ScopeSweep {
        report: SweepReport {
            runs: vec![(
                connector.to_string(),
                Outcome::Planned(Box::new(
                    planned(&[("nobody", "u-nobody")], &BTreeSet::new()).await,
                )),
            )],
        },
        terms: BTreeMap::new(),
    };
    let applied = apply_sweep(store, scope, &env, &orphan).await;

    assert!(
        applied.snapshots.is_empty(),
        "a connector nothing was applied for recorded a snapshot: {:?}",
        applied.snapshots
    );
    assert_eq!(applied.total.provisioned, 0);
    assert_eq!(snapshot_of(store, scope, &connector).await, None);
}
