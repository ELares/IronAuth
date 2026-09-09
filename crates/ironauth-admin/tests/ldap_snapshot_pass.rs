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
    ApplyTerms, PassReport, ScopeSweep, fold_scope, previous_for, reconciled, schedule_for,
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
    NewLdapConnector, OrganizationId, Scope, ScopeSnapshots, ServiceId, Store, UserState,
};
use serde_json::json;
use sqlx::Row;

struct Fake {
    people: Vec<DirectoryEntry>,
    /// Group DN to its members. Empty means the connector syncs everybody under the user base.
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

/// A plan for a directory holding exactly `people`, diffed against `previous`.
async fn planned(people: &[(&str, &str)], previous: &BTreeSet<String>) -> SyncPlan {
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
            None,
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
            timings: BTreeMap::new(),
        },
        terms: BTreeMap::from([(connector.to_string(), terms)]),
        skipped: Vec::new(),
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

/// An account provisioned by something that is NOT this connector -- a SCIM push, an import.
///
/// Without one, "a first pass removes nobody" is satisfied by there being nobody to remove: the
/// executor scores a removal for a principal with no account as `already_absent`, never as a
/// deactivation, so the assertion could not fail on an empty scope.
async fn seed_bystander(db: &TestDatabase, env: &Env, scope: Scope) {
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .users()
        .admin_create(
            env,
            ironauth_store::NewAdminUser {
                id: None,
                identifier: "scim-provisioned",
                password_hash: None,
                claims_json: None,
                external_id: Some("u-from-scim"),
                state: UserState::Active,
                foreign_password_hash: None,
                foreign_password_algo: None,
                traits: None,
            },
            now(env),
            None,
        )
        .await
        .expect("seed the bystander");
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

    seed_bystander(&db, &env, scope).await;

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
    assert_eq!(
        state_of(store, scope, "u-from-scim").await,
        Some(UserState::Active),
        "the first pass deprovisioned an account this connector never provisioned"
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

    // And Wednesday, unchanged: the repeat must be QUIET. `deactivated == 0` alone cannot say
    // that -- a pass that re-derives every principal as an arrival scores `already_present`, not
    // a failure and not a deactivation, so the whole tuple is asserted.
    let wednesday = one_pass(&db, &env, scope, &connector, &[("ada", "u-ada")], soft).await;
    assert_eq!(
        (
            wednesday.applied.provisioned,
            wednesday.applied.already_present,
            wednesday.applied.deactivated,
            wednesday.applied.deleted,
            wednesday.applied.already_removed
        ),
        (0, 0, 0, 0, 0),
        "an unchanged directory must produce no change set at all: {wednesday:?}"
    );
    assert!(
        wednesday.applied.everything_applied(),
        "{:?}",
        wednesday.applied.failures
    );
    assert_eq!(
        state_of(store, scope, "u-from-scim").await,
        Some(UserState::Active),
        "the bystander was deprovisioned once the snapshot existed"
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

/// A GROUP-SCOPED CONNECTOR RECORDS ITS MEMBERS, NOT THE WHOLE USER BASE. `arrivals ∪ retained`
/// is the plan's in-scope set; `present` is everybody the search returned. They differ only when
/// the connector names group roots, which no other fixture does -- so without this test the two
/// are indistinguishable and recording `present` passes.
///
/// The consequence of getting it wrong is the one the diff exists to refuse: everybody outside
/// the synced group lands in the snapshot, and the NEXT pass computes them as departures.
#[tokio::test]
async fn a_group_scoped_connector_records_only_the_group_members() {
    let inside = person("ada", "u-ada");
    let outside = person("outsider", "u-outsider");
    let fake = Fake {
        people: vec![inside, outside],
        groups: BTreeMap::from([(
            "cn=eng,ou=Groups,dc=example,dc=test".to_owned(),
            vec![Member {
                dn: "uid=ada,ou=People,dc=example,dc=test".to_owned(),
                is_group: false,
            }],
        )]),
    };
    let scoped = plan(
        &fake,
        &SyncInputs {
            user_base_dn: "ou=People,dc=example,dc=test".to_owned(),
            user_filter: "(objectClass=inetOrgPerson)".to_owned(),
            group_roots: vec!["cn=eng,ou=Groups,dc=example,dc=test".to_owned()],
            max_group_depth: 5,
            attribute_mapping: json!({ "username": "uid" }),
        },
        &BTreeSet::new(),
    )
    .await
    .expect("plans");

    assert_eq!(
        scoped.present.len(),
        2,
        "both people must be READ, or the two implementations stay indistinguishable"
    );

    let changes = ChangeSet::from_plan(&scoped, LdapAbsencePolicy::Deactivate);
    let clean = ironauth_admin::ldap_execute::ExecuteReport::default();
    let recorded = reconciled(&scoped, &changes, &clean).expect("a complete observation");

    assert_eq!(
        recorded,
        BTreeSet::from(["u-ada".to_owned()]),
        "somebody the connector does not sync went into the snapshot, and the next pass would \
         deprovision them: {recorded:?}"
    );
}

/// AN UNREADABLE SNAPSHOT TAKES ITS CONNECTOR OUT OF THE SWEEP ENTIRELY, and leaves every other
/// connector in it. Sweeping it against an empty previous set would read its whole directory as
/// new, and the pass after -- with a fresh snapshot in place -- would conclude that nobody had
/// ever left it, forgetting everybody who departed while the row was unreadable.
#[tokio::test]
async fn a_connector_whose_snapshot_will_not_open_is_not_swept() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let healthy = seed_connector(&db, &env, scope, LdapAbsencePolicy::Deactivate).await;
    let corrupt = seed_connector(&db, &env, scope, LdapAbsencePolicy::Deactivate).await;
    let store = db.control_store();
    let rows = store
        .scoped(scope)
        .ldap_connectors()
        .active_in_scope(100)
        .await
        .expect("read the connectors");

    let snapshots = ScopeSnapshots {
        opened: BTreeMap::from([(healthy.to_string(), BTreeSet::from(["u-a".to_owned()]))]),
        unreadable: BTreeSet::from([corrupt.to_string()]),
    };
    let (scheduled, skipped) = schedule_for(&rows, &snapshots, &|c| previous_for(&snapshots, c));

    assert_eq!(
        skipped,
        vec![corrupt.to_string()],
        "the connector with the unreadable snapshot was swept anyway"
    );
    assert_eq!(
        scheduled.iter().map(|s| s.id.clone()).collect::<Vec<_>>(),
        vec![healthy.to_string()],
        "the healthy connector was dropped with the corrupt one"
    );
    assert_eq!(
        scheduled[0].previous,
        BTreeSet::from(["u-a".to_owned()]),
        "the healthy connector lost its previous set"
    );
}

/// AND WITH NO UNREADABLE ROWS, everybody is swept. Without this the test above passes on a
/// `schedule_for` that skips every connector unconditionally.
#[tokio::test]
async fn every_connector_is_swept_when_no_snapshot_is_broken() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    seed_connector(&db, &env, scope, LdapAbsencePolicy::Deactivate).await;
    seed_connector(&db, &env, scope, LdapAbsencePolicy::Deactivate).await;
    let rows = db
        .control_store()
        .scoped(scope)
        .ldap_connectors()
        .active_in_scope(100)
        .await
        .expect("read the connectors");

    let clean = ScopeSnapshots::default();
    let (scheduled, skipped) = schedule_for(&rows, &clean, &|c| previous_for(&clean, c));

    assert_eq!(scheduled.len(), 2, "a healthy scope must sweep everybody");
    assert!(skipped.is_empty(), "{skipped:?}");
}

/// AND THE PASS COUNTS WHAT THE SWEEP REFUSED TO RUN. A pass that skipped every directory must
/// not be an INFO line saying nothing happened -- `snapshots_unreadable` is what the daemon's
/// needs-attention predicate reads.
#[tokio::test]
async fn a_skipped_connector_is_counted_by_the_pass() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.control_store();
    let connector = seed_connector(&db, &env, scope, LdapAbsencePolicy::Deactivate).await;

    let mut sweep = sweep_of(
        &connector,
        planned(&[("a", "u-a")], &BTreeSet::new()).await,
        terms(&connector, LdapAbsencePolicy::Deactivate),
    );
    sweep.skipped.push("ldc_unreadable".to_owned());

    let mut report = PassReport::default();
    fold_scope(store, scope, &env, &db.master_key(), &sweep, &mut report).await;

    assert_eq!(
        report.snapshots_unreadable, 1,
        "a connector the sweep refused to run was not counted: {report:?}"
    );
    assert_eq!(
        report.applied.provisioned, 1,
        "the connector that WAS swept must still apply"
    );
}

/// THE PASS WRITES HEALTH FOR EVERY CONNECTOR IT TOUCHED, including the one it could not reach.
/// A health surface that only records successes answers "is this directory syncing" with silence,
/// which is exactly the question the isolation criterion is about.
#[tokio::test]
async fn a_pass_records_health_for_the_reachable_and_the_unreachable_alike() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.control_store();
    let soft = LdapAbsencePolicy::Deactivate;
    let live = seed_connector(&db, &env, scope, soft).await;
    let dead = seed_connector(&db, &env, scope, soft).await;

    let mut sweep = sweep_of(
        &live,
        planned(&[("a", "u-a"), ("b", "u-b")], &BTreeSet::new()).await,
        terms(&live, soft),
    );
    sweep.report.runs.push((
        dead.to_string(),
        Outcome::Unreachable("connection refused".to_owned()),
    ));
    sweep.terms.insert(dead.to_string(), terms(&dead, soft));

    let mut report = PassReport::default();
    fold_scope(store, scope, &env, &db.master_key(), &sweep, &mut report).await;

    assert_eq!(
        report.health_recorded, 2,
        "health must be written for both, not only the one that worked: {report:?}"
    );
    assert_eq!(report.health_unrecorded, 0);

    let healthy = store
        .scoped(scope)
        .ldap_sync_runs()
        .get(&live)
        .await
        .expect("read")
        .expect("the reachable connector has health");
    assert_eq!(healthy.outcome, ironauth_store::LdapRunOutcome::Planned);
    assert_eq!(
        healthy.provisioned, 2,
        "the counts must be this connector's, not the scope's sum: {healthy:?}"
    );
    assert!(
        healthy.duration_ms >= 0,
        "a measured duration cannot be negative: {healthy:?}"
    );
    assert!(healthy.is_healthy());

    let broken = store
        .scoped(scope)
        .ldap_sync_runs()
        .get(&dead)
        .await
        .expect("read")
        .expect("the unreachable connector has health");
    assert_eq!(broken.outcome, ironauth_store::LdapRunOutcome::Unreachable);
    // A CATEGORY, NOT THE SERVER'S MESSAGE. The raw text can carry a DN, and the sibling snapshot
    // table seals identifiers for exactly that reason.
    assert_eq!(
        broken.error.as_deref(),
        Some("the directory could not be opened; see the log")
    );
    assert!(
        !broken
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("connection refused"),
        "the directory's own message reached the health column"
    );
    assert_eq!(broken.consecutive_failures, 1);
    assert_eq!(
        broken.provisioned, 0,
        "a connector that never opened cannot have provisioned anybody"
    );
    assert!(!broken.is_healthy());

    let unhealthy = store
        .scoped(scope)
        .ldap_sync_runs()
        .unhealthy_in_scope()
        .await
        .expect("read");
    assert_eq!(unhealthy.len(), 1, "{unhealthy:?}");
    assert_eq!(unhealthy[0].connector_id, dead.to_string());
}

/// TWO SUCCESSFUL CONNECTORS WITH DIFFERENT COUNTS. With only one connector producing counts,
/// its own number and the scope-wide sum are the same value, so "these are this connector's
/// counts" cannot fail -- and neither can a mix-up that gives every planned connector the first
/// one's counts. Two successes with different sizes is the fixture that separates them.
#[tokio::test]
async fn each_connector_gets_its_own_counts_not_its_neighbours() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.control_store();
    let soft = LdapAbsencePolicy::Deactivate;
    let small = seed_connector(&db, &env, scope, soft).await;
    let large = seed_connector(&db, &env, scope, soft).await;

    let mut sweep = sweep_of(
        &small,
        planned(&[("s1", "u-s1")], &BTreeSet::new()).await,
        terms(&small, soft),
    );
    sweep.report.runs.push((
        large.to_string(),
        Outcome::Planned(Box::new(
            planned(
                &[("l1", "u-l1"), ("l2", "u-l2"), ("l3", "u-l3")],
                &BTreeSet::new(),
            )
            .await,
        )),
    ));
    sweep.terms.insert(large.to_string(), terms(&large, soft));

    let mut report = PassReport::default();
    fold_scope(store, scope, &env, &db.master_key(), &sweep, &mut report).await;
    assert_eq!(report.applied.provisioned, 4, "the scope-wide sum");

    let one = store
        .scoped(scope)
        .ldap_sync_runs()
        .get(&small)
        .await
        .expect("read")
        .expect("present");
    let three = store
        .scoped(scope)
        .ldap_sync_runs()
        .get(&large)
        .await
        .expect("read")
        .expect("present");

    assert_eq!(
        (one.provisioned, three.provisioned),
        (1, 3),
        "one connector's counts landed on the other's health row, or both got the scope sum"
    );
}

/// A CONNECTOR THE APPLIER DECLINED IS NOT A FRESH SUCCESS. Writing `planned` for it would zero
/// its failure counter and advance `last_success_at` -- the staleness signal the recovery story
/// leans on -- for a pass that synced nobody.
#[tokio::test]
async fn a_connector_the_applier_declined_is_not_recorded_healthy() {
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
            timings: BTreeMap::new(),
        },
        terms: BTreeMap::new(),
        skipped: Vec::new(),
    };
    let mut report = PassReport::default();
    fold_scope(store, scope, &env, &db.master_key(), &orphan, &mut report).await;

    let health = store
        .scoped(scope)
        .ldap_sync_runs()
        .get(&connector)
        .await
        .expect("read")
        .expect("a declined connector still gets a health row");
    assert_eq!(
        health.outcome,
        ironauth_store::LdapRunOutcome::Skipped,
        "a connector nothing was applied for was recorded as a success: {health:?}"
    );
    assert!(health.error.is_some(), "a decline has to say why");
    assert!(!health.is_healthy());
    assert_eq!(
        health.last_success_at_unix_micros, None,
        "a pass that synced nobody advanced the last-success instant"
    );
}

/// A REPORT KEY THAT IS NOT A CONNECTOR ID IS COUNTED. A connector with no health row leaves the
/// previous pass's answer standing, and a counter that does not move keeps the boot loop quiet.
#[tokio::test]
async fn an_unkeyable_report_entry_is_counted_rather_than_dropped() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.control_store();
    let soft = LdapAbsencePolicy::Deactivate;
    let real = seed_connector(&db, &env, scope, soft).await;

    let mut sweep = sweep_of(
        &real,
        planned(&[("a", "u-a")], &BTreeSet::new()).await,
        terms(&real, soft),
    );
    sweep.report.runs.push((
        "not-a-connector-id".to_owned(),
        Outcome::Unreachable("nowhere".to_owned()),
    ));

    let mut report = PassReport::default();
    fold_scope(store, scope, &env, &db.master_key(), &sweep, &mut report).await;

    assert_eq!(report.health_recorded, 1, "{report:?}");
    assert_eq!(
        report.health_unrecorded, 1,
        "the entry with no usable key was dropped without a count: {report:?}"
    );
}

/// THE MEASURED TIMING REACHES THE ROW. `duration_ms` and `started_at` were both invented at the
/// writer -- a literal 0 and one scope-wide clock read -- behind a column comment promising an
/// end-to-end measurement. The sweep measures them per connector now; this pins that the health
/// row carries what the sweep measured rather than anything the writer made up.
#[tokio::test]
async fn the_health_row_carries_the_timing_the_sweep_measured() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.control_store();
    let soft = LdapAbsencePolicy::Deactivate;
    let connector = seed_connector(&db, &env, scope, soft).await;

    let mut sweep = sweep_of(
        &connector,
        planned(&[("a", "u-a")], &BTreeSet::new()).await,
        terms(&connector, soft),
    );
    // Values no clock in this test could produce, so a writer that ignored them is visible.
    sweep.report.timings.insert(
        connector.to_string(),
        ironauth_admin::ldap_schedule::RunTiming {
            started_at_unix_micros: 1_767_323_045_678_901,
            duration_ms: 4_242,
        },
    );

    let mut report = PassReport::default();
    fold_scope(store, scope, &env, &db.master_key(), &sweep, &mut report).await;

    let health = store
        .scoped(scope)
        .ldap_sync_runs()
        .get(&connector)
        .await
        .expect("read")
        .expect("present");
    assert_eq!(
        (health.started_at_unix_micros, health.duration_ms),
        (1_767_323_045_678_901, 4_242),
        "the health row invented its own timing instead of carrying the sweep's: {health:?}"
    );
    assert_eq!(
        health.last_success_at_unix_micros,
        Some(1_767_323_045_678_901),
        "the last-success instant must be when the connector was actually reached"
    );
}

/// AND THE SWEEP REALLY MEASURES. A timing map the sweep never filled would make the test above
/// pass on hand-built input while every real pass still wrote zeros.
#[tokio::test]
async fn the_sweep_measures_a_timing_for_every_connector_it_ran() {
    use ironauth_admin::ldap_schedule::{Scheduled, SourceFactory, sweep};

    /// A directory that takes a measurable moment to refuse. Without the wait, a real
    /// measurement and a hardcoded zero are the same number.
    struct SlowToRefuse;
    impl SourceFactory for SlowToRefuse {
        type Source = Fake;
        type Error = std::io::Error;
        async fn open(&self, _s: &Scheduled) -> Result<Self::Source, Self::Error> {
            tokio::time::sleep(std::time::Duration::from_millis(60)).await;
            Err(std::io::Error::other("no directory here"))
        }
    }

    let env = Env::system();
    let scheduled: Vec<Scheduled> = ["ldc_a", "ldc_b"]
        .iter()
        .map(|id| Scheduled {
            id: (*id).to_owned(),
            previous: BTreeSet::new(),
            inputs: SyncInputs {
                user_base_dn: "ou=People,dc=example,dc=test".to_owned(),
                user_filter: "(objectClass=inetOrgPerson)".to_owned(),
                group_roots: Vec::new(),
                max_group_depth: 5,
                attribute_mapping: json!({ "username": "uid" }),
            },
        })
        .collect();

    let report = sweep(
        &SlowToRefuse,
        &scheduled,
        std::time::Duration::from_secs(5),
        &env,
    )
    .await;

    assert_eq!(
        report.timings.len(),
        2,
        "a connector ran without being timed"
    );
    for id in ["ldc_a", "ldc_b"] {
        let timing = report.timings.get(id).expect("timed");
        assert!(
            timing.started_at_unix_micros > 1_700_000_000_000_000,
            "the start instant is not a real clock read: {timing:?}"
        );
        // THE DURATION IS MEASURED, not defaulted. Each attempt waits 60ms before failing, so a
        // writer that reports zero -- which is what shipped before this -- is visible here.
        assert!(
            timing.duration_ms >= 40,
            "the duration is not a measurement: {timing:?}"
        );
    }
}

/// AND A SKIPPED CONNECTOR SAYS SO. A directory not being swept at all is the loudest state
/// there is; recording nothing for it would leave the previous pass's answer standing.
#[tokio::test]
async fn a_skipped_connector_records_its_own_health() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.control_store();
    let soft = LdapAbsencePolicy::Deactivate;
    let live = seed_connector(&db, &env, scope, soft).await;
    let skipped = seed_connector(&db, &env, scope, soft).await;

    let mut sweep = sweep_of(
        &live,
        planned(&[("a", "u-a")], &BTreeSet::new()).await,
        terms(&live, soft),
    );
    sweep.skipped.push(skipped.to_string());

    let mut report = PassReport::default();
    fold_scope(store, scope, &env, &db.master_key(), &sweep, &mut report).await;

    assert_eq!(report.health_recorded, 2, "{report:?}");
    let health = store
        .scoped(scope)
        .ldap_sync_runs()
        .get(&skipped)
        .await
        .expect("read")
        .expect("the skipped connector has health");
    assert_eq!(health.outcome, ironauth_store::LdapRunOutcome::Skipped);
    assert!(health.error.is_some(), "a skip has to say why");
    assert!(!health.is_healthy());
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

/// THE RECORD-FAILURE ARM. Nothing reached it before, so the counter, the log and the whole arm
/// could have been deleted with every test green. The previous snapshot survives a failed write,
/// which is what makes the pass after it still detect the departure -- against a staler baseline.
#[tokio::test]
async fn a_snapshot_that_cannot_be_written_is_counted_and_the_baseline_survives() {
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
    let baseline = snapshot_of(store, scope, &connector).await;
    assert_eq!(
        baseline,
        Some(BTreeSet::from(["u-a".to_owned(), "u-b".to_owned()]))
    );

    // Take the write grant away, exactly as a misprovisioned role would.
    db.execute_owner_sql("REVOKE INSERT, UPDATE ON ldap_sync_snapshots FROM ironauth_control")
        .await;
    let blocked = one_pass(&db, &env, scope, &connector, &[("a", "u-a")], soft).await;
    db.execute_owner_sql("GRANT INSERT ON ldap_sync_snapshots TO ironauth_control")
        .await;
    db.execute_owner_sql(
        "GRANT UPDATE (dek_version, ciphertext, principal_count, taken_at) \
         ON ldap_sync_snapshots TO ironauth_control",
    )
    .await;

    assert_eq!(
        (blocked.snapshots_recorded, blocked.snapshots_unrecorded),
        (0, 1),
        "a snapshot write that failed was not counted: {blocked:?}"
    );
    assert_eq!(
        blocked.applied.deactivated, 1,
        "the departure itself still applied"
    );
    assert_eq!(
        snapshot_of(store, scope, &connector).await,
        baseline,
        "a failed write must leave the previous baseline standing"
    );

    // The next pass compares against the STALER baseline and re-applies idempotently, which is
    // what makes a failed write survivable rather than terminal.
    let after = one_pass(&db, &env, scope, &connector, &[("a", "u-a")], soft).await;
    assert!(
        after.applied.everything_applied(),
        "{:?}",
        after.applied.failures
    );
    assert_eq!(
        after.applied.already_removed, 1,
        "the staler baseline must re-derive the same departure and find it already done: {after:?}"
    );
    assert_eq!(after.snapshots_recorded, 1);
}

/// A SNAPSHOT THAT WILL NOT OPEN SKIPS ITS CONNECTOR, and only its connector. Before, one bad
/// blob made `all_in_scope` return `Err` and `run_pass` abandoned every scope in the deployment.
#[tokio::test]
async fn an_unreadable_snapshot_is_reported_and_does_not_hide_the_others() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.control_store();
    let soft = LdapAbsencePolicy::Deactivate;
    let healthy = seed_connector(&db, &env, scope, soft).await;
    let corrupt = seed_connector(&db, &env, scope, soft).await;

    one_pass(&db, &env, scope, &healthy, &[("a", "u-a")], soft).await;
    one_pass(&db, &env, scope, &corrupt, &[("b", "u-b")], soft).await;

    // The lift the seal is designed to refuse: one connector's ciphertext on another's row.
    let stolen: Vec<u8> =
        sqlx::query("SELECT ciphertext FROM ldap_sync_snapshots WHERE connector_id = $1")
            .bind(healthy.to_string())
            .fetch_one(db.owner_pool())
            .await
            .expect("read")
            .get("ciphertext");
    sqlx::query("UPDATE ldap_sync_snapshots SET ciphertext = $1 WHERE connector_id = $2")
        .bind(&stolen)
        .bind(corrupt.to_string())
        .execute(db.owner_pool())
        .await
        .expect("corrupt the row");

    let all = store
        .scoped(scope)
        .ldap_sync_snapshots()
        .all_in_scope()
        .await
        .expect("one bad blob must not fail the read");

    assert_eq!(
        all.unreadable,
        BTreeSet::from([corrupt.to_string()]),
        "the unreadable row was not reported as unreadable: {all:?}"
    );
    assert_eq!(
        all.opened.get(&healthy.to_string()),
        Some(&BTreeSet::from(["u-a".to_owned()])),
        "the healthy connector was lost with the corrupt one"
    );
    assert!(
        !all.opened.contains_key(&corrupt.to_string()),
        "an unreadable snapshot must NOT read as an empty one"
    );
}

/// A CONNECTOR WITH NO POLICY RECORDS NOTHING EITHER. Nothing was applied for it, so recording
/// what its directory held would tell the next pass that IronAuth had agreed with a read it never
/// acted on -- and everybody in it would be silently forgotten.
///
/// THROUGH `fold_scope`, not `apply_sweep`: `apply_sweep` never touches the table, so a database
/// assertion after it is true whatever it does. `fold_scope` is the writer.
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
            timings: BTreeMap::new(),
        },
        terms: BTreeMap::new(),
        skipped: Vec::new(),
    };
    let mut report = PassReport::default();
    fold_scope(store, scope, &env, &db.master_key(), &orphan, &mut report).await;

    assert_eq!(
        report.applied.provisioned, 0,
        "a connector with no policy was applied"
    );
    assert_eq!(
        (report.snapshots_recorded, report.snapshots_unrecorded),
        (0, 0),
        "a connector nothing was applied for reached the recorder: {report:?}"
    );
    assert_eq!(
        snapshot_of(store, scope, &connector).await,
        None,
        "a connector with no policy left a snapshot behind"
    );
    assert_eq!(
        state_of(store, scope, "u-nobody").await,
        None,
        "a connector with no policy provisioned somebody"
    );
}
