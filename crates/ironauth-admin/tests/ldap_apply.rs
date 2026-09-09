// SPDX-License-Identifier: MIT OR Apache-2.0

//! Applying what a sweep planned (issue #142), over a real database and no directory.
//!
//! [`apply_sweep`] takes a sweep report rather than opening connections, which is what makes the
//! applied-versus-planned properties testable at all: a live LDAP server can be pointed at a
//! fixture, but it cannot be made to produce a plan for a connector whose policy went missing, or
//! two connectors with opposite policies in one pass.

#![cfg(feature = "testing")]

use std::collections::{BTreeMap, BTreeSet};

use ironauth_admin::ldap_boot::{ApplyTerms, ScopeSweep, apply_sweep, terms_for};
use ironauth_admin::ldap_groups::{GroupSource, Member};
use ironauth_admin::ldap_mapping::DirectoryEntry;
use ironauth_admin::ldap_schedule::{Outcome, SweepReport};
use ironauth_admin::ldap_sync::{EntrySource, SyncInputs, SyncPlan, plan};
use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ActorRef, LdapAbsencePolicy, LdapConnector, LdapConnectorId, LdapTlsMode, OrganizationId,
    Scope, ServiceId, Store, UserState,
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

async fn planned(people: &[(&str, &str)], previous: &[&str]) -> SyncPlan {
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
        &previous
            .iter()
            .map(|s| (*s).to_owned())
            .collect::<BTreeSet<String>>(),
    )
    .await
    .expect("plans")
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

/// A sweep report naming one connector per entry, with the terms each is applied under.
fn sweep(entries: Vec<(&str, SyncPlan, ApplyTerms)>) -> ScopeSweep {
    let mut runs = Vec::new();
    let mut terms = BTreeMap::new();
    for (id, plan, term) in entries {
        runs.push((id.to_owned(), Outcome::Planned(Box::new(plan))));
        terms.insert(id.to_owned(), term);
    }
    ScopeSweep {
        report: SweepReport { runs },
        terms,
    }
}

fn terms(env: &Env, policy: LdapAbsencePolicy) -> ApplyTerms {
    ApplyTerms {
        policy,
        actor: ActorRef::service(ServiceId::generate(env)),
    }
}

/// THE PASS WRITES. Before this wiring a pass produced plans and dropped them, which is the
/// forever-alive-account failure #142 is defined against; the arrival half of the fix is that a
/// planned connector's arrivals become accounts.
#[tokio::test]
async fn a_planned_connector_provisions_its_arrivals() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.control_store();

    let one = planned(&[("ada", "u-ada"), ("grace", "u-grace")], &[]).await;
    let report = apply_sweep(
        store,
        scope,
        &env,
        &sweep(vec![(
            "ldc_one",
            one,
            terms(&env, LdapAbsencePolicy::Deactivate),
        )]),
    )
    .await;

    assert!(report.everything_applied(), "{:?}", report.failures);
    assert_eq!(report.provisioned, 2);
    assert_eq!(
        state_of(store, scope, "u-ada").await,
        Some(UserState::Active)
    );
    assert_eq!(
        state_of(store, scope, "u-grace").await,
        Some(UserState::Active)
    );

    // AND THE HOUR AFTER. The sweep runs on a ticker with the same empty snapshot every time, so
    // the SECOND pass over an unchanged directory is the ordinary case, not an edge one.
    let again = apply_sweep(
        store,
        scope,
        &env,
        &sweep(vec![(
            "ldc_one",
            planned(&[("ada", "u-ada"), ("grace", "u-grace")], &[]).await,
            terms(&env, LdapAbsencePolicy::Deactivate),
        )]),
    )
    .await;
    assert_eq!(again.provisioned, 0, "the second pass created them again");
    assert_eq!(
        again.already_present, 2,
        "the second pass did not recognise its own accounts: {again:?}"
    );
    assert!(again.everything_applied(), "{:?}", again.failures);
}

/// A DEPARTURE WITH NO ACCOUNT IS ABSENT, NOT FAILED. A stable id in the previous snapshot that
/// never became an account -- a clash last pass, a manual deletion -- must not make every later
/// pass report a failure for the same principal for ever.
#[tokio::test]
async fn a_departure_with_no_account_is_counted_absent_rather_than_failed() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.control_store();

    apply_sweep(
        store,
        scope,
        &env,
        &sweep(vec![(
            "ldc_one",
            planned(&[("real", "u-real")], &[]).await,
            terms(&env, LdapAbsencePolicy::Deactivate),
        )]),
    )
    .await;

    // `u-ghost` was in the previous snapshot and has no account; `u-real` stays, so the
    // observation is not the refused everybody-vanished shape.
    let report = apply_sweep(
        store,
        scope,
        &env,
        &sweep(vec![(
            "ldc_one",
            planned(&[("real", "u-real")], &["u-real", "u-ghost"]).await,
            terms(&env, LdapAbsencePolicy::Deactivate),
        )]),
    )
    .await;

    assert!(
        report.everything_applied(),
        "a departure with no account was reported as a failure: {:?}",
        report.failures
    );
    assert_eq!(
        report.already_absent, 1,
        "the absent departure was not counted: {report:?}"
    );
    assert_eq!(report.deactivated, 0);
    assert_eq!(
        state_of(store, scope, "u-real").await,
        Some(UserState::Active),
        "the principal still in the directory was removed"
    );
}

/// EACH CONNECTOR UNDER ITS OWN POLICY. One pass, two connectors, opposite absence policies: the
/// deactivating one must leave a disabled row and the deleting one must leave nothing. A pass that
/// read the policy once and reused it would pass every single-connector test and destroy accounts
/// here.
///
/// Each directory KEEPS somebody. An emptied directory is refused as a departure signal entirely
/// (the next test), so a fixture where everybody leaves cannot show a policy being applied.
#[tokio::test]
async fn two_connectors_in_one_pass_apply_their_own_policies() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.control_store();

    apply_sweep(
        store,
        scope,
        &env,
        &sweep(vec![
            (
                "ldc_soft",
                planned(&[("softy", "u-soft"), ("softkeep", "u-soft-keep")], &[]).await,
                terms(&env, LdapAbsencePolicy::Deactivate),
            ),
            (
                "ldc_hard",
                planned(&[("hardy", "u-hard"), ("hardkeep", "u-hard-keep")], &[]).await,
                terms(&env, LdapAbsencePolicy::Delete),
            ),
        ]),
    )
    .await;
    assert_eq!(
        state_of(store, scope, "u-soft").await,
        Some(UserState::Active),
        "the arrival half has to have happened, or the departure below proves nothing"
    );
    assert_eq!(
        state_of(store, scope, "u-hard").await,
        Some(UserState::Active)
    );

    // One principal leaves each directory; the other stays, so the observation is credible.
    let report = apply_sweep(
        store,
        scope,
        &env,
        &sweep(vec![
            (
                "ldc_soft",
                planned(&[("softkeep", "u-soft-keep")], &["u-soft", "u-soft-keep"]).await,
                terms(&env, LdapAbsencePolicy::Deactivate),
            ),
            (
                "ldc_hard",
                planned(&[("hardkeep", "u-hard-keep")], &["u-hard", "u-hard-keep"]).await,
                terms(&env, LdapAbsencePolicy::Delete),
            ),
        ]),
    )
    .await;

    assert!(report.everything_applied(), "{:?}", report.failures);
    assert_eq!(report.deactivated, 1, "exactly one connector deactivates");
    assert_eq!(report.deleted, 1, "exactly one connector deletes");
    assert_eq!(
        state_of(store, scope, "u-soft").await,
        Some(UserState::Disabled),
        "the deactivating connector's principal was deleted, or left alone"
    );
    assert_eq!(
        state_of(store, scope, "u-hard").await,
        None,
        "the deleting connector's principal survived"
    );
    assert_eq!(
        state_of(store, scope, "u-soft-keep").await,
        Some(UserState::Active),
        "somebody still in the directory was removed"
    );
    assert_eq!(
        state_of(store, scope, "u-hard-keep").await,
        Some(UserState::Active),
        "somebody still in the directory was removed"
    );
}

/// THE REFUSAL REACHES THE WRITES. A directory that answers with nobody is the shape of a failure,
/// not of a company that all resigned, and [`ironauth_admin::ldap_diff`] refuses to call it a
/// departure. That refusal is only worth anything if the applier honours it: this is the mass
/// deprovisioning that must not happen, run against a real database.
#[tokio::test]
async fn an_emptied_directory_removes_nobody() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.control_store();

    apply_sweep(
        store,
        scope,
        &env,
        &sweep(vec![(
            "ldc_only",
            planned(&[("a", "u-a"), ("b", "u-b")], &[]).await,
            terms(&env, LdapAbsencePolicy::Delete),
        )]),
    )
    .await;

    let vanished = planned(&[], &["u-a", "u-b"]).await;
    assert!(
        vanished.departures.is_err(),
        "the fixture must be the refused shape, or this test asserts nothing"
    );
    let report = apply_sweep(
        store,
        scope,
        &env,
        &sweep(vec![(
            "ldc_only",
            vanished,
            terms(&env, LdapAbsencePolicy::Delete),
        )]),
    )
    .await;

    assert_eq!(report.deleted, 0);
    assert_eq!(report.deactivated, 0);
    assert!(report.everything_applied(), "{:?}", report.failures);
    assert_eq!(
        state_of(store, scope, "u-a").await,
        Some(UserState::Active),
        "an empty directory read deprovisioned a real user"
    );
    assert_eq!(state_of(store, scope, "u-b").await, Some(UserState::Active));
}

/// A CONNECTOR WITH NO TERMS IS SKIPPED, not defaulted. The only way a plan arrives without its
/// policy is a report and a term map that disagree, and picking either policy from a disagreement
/// is a guess -- one of whose branches is irreversible.
#[tokio::test]
async fn a_plan_whose_policy_is_missing_applies_nothing() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.control_store();

    // Seed through a connector that does have terms, so there is something to destroy.
    apply_sweep(
        store,
        scope,
        &env,
        &sweep(vec![(
            "ldc_known",
            planned(&[("victim", "u-victim")], &[]).await,
            terms(&env, LdapAbsencePolicy::Delete),
        )]),
    )
    .await;
    assert_eq!(
        state_of(store, scope, "u-victim").await,
        Some(UserState::Active)
    );

    let orphan = ScopeSweep {
        report: SweepReport {
            runs: vec![(
                "ldc_orphan".to_owned(),
                Outcome::Planned(Box::new(
                    planned(&[("newby", "u-newby")], &["u-victim"]).await,
                )),
            )],
        },
        terms: BTreeMap::new(),
    };
    let report = apply_sweep(store, scope, &env, &orphan).await;

    assert_eq!(report.provisioned, 0, "no arrival may be written either");
    assert_eq!(report.deleted, 0);
    assert_eq!(report.deactivated, 0);
    assert!(report.everything_applied(), "{:?}", report.failures);
    assert_eq!(
        state_of(store, scope, "u-victim").await,
        Some(UserState::Active),
        "a plan with no policy took the irreversible branch"
    );
    assert_eq!(
        state_of(store, scope, "u-newby").await,
        None,
        "a plan with no policy was applied anyway"
    );
}

/// AN OUTCOME THAT IS NOT A PLAN WRITES NOTHING. An unreachable directory is the case that must
/// never read as an empty one: `Unreachable` carries no plan, so there is nothing to apply, and
/// the connector beside it in the same pass still gets applied.
#[tokio::test]
async fn an_unreachable_connector_writes_nothing_and_does_not_stop_its_neighbour() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.control_store();

    let mut mixed = sweep(vec![(
        "ldc_live",
        planned(&[("live", "u-live")], &[]).await,
        terms(&env, LdapAbsencePolicy::Delete),
    )]);
    mixed.report.runs.insert(
        0,
        (
            "ldc_dead".to_owned(),
            Outcome::Unreachable("connection refused".to_owned()),
        ),
    );
    mixed.terms.insert(
        "ldc_dead".to_owned(),
        terms(&env, LdapAbsencePolicy::Delete),
    );

    let report = apply_sweep(store, scope, &env, &mixed).await;

    assert!(report.everything_applied(), "{:?}", report.failures);
    assert_eq!(
        report.provisioned, 1,
        "the reachable connector's arrival is the whole point of the isolation"
    );
    // EVERY OTHER COUNTER IS ZERO. Asserting only the provision would let an outcome with no plan
    // contribute to the tally -- an unreachable directory reporting activity it did not have.
    assert_eq!(
        (
            report.already_present,
            report.deactivated,
            report.deleted,
            report.already_absent
        ),
        (0, 0, 0, 0),
        "an outcome carrying no plan was counted as work: {report:?}"
    );
    assert_eq!(
        state_of(store, scope, "u-live").await,
        Some(UserState::Active)
    );
}

/// A FAILURE SURVIVES THE SUMMING. A pass folds each connector's report into one, and a fold that
/// drops the failure list reports a clean pass over a directory half of which did not apply. The
/// clash is a real directory state: two principals whose mapped login is the same.
#[tokio::test]
async fn a_failing_change_is_named_in_the_summed_report() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.control_store();

    let clashing = Fake {
        people: vec![
            DirectoryEntry::new(
                "uid=dup,ou=A,dc=example,dc=test".to_owned(),
                vec![
                    ("uid".to_owned(), vec!["dup".to_owned()]),
                    ("entryUUID".to_owned(), vec!["u-first".to_owned()]),
                ],
            ),
            DirectoryEntry::new(
                "uid=dup,ou=B,dc=example,dc=test".to_owned(),
                vec![
                    ("uid".to_owned(), vec!["dup".to_owned()]),
                    ("entryUUID".to_owned(), vec!["u-second".to_owned()]),
                ],
            ),
        ],
    };
    let with_a_clash = plan(
        &clashing,
        &SyncInputs {
            user_base_dn: "dc=example,dc=test".to_owned(),
            user_filter: "(objectClass=inetOrgPerson)".to_owned(),
            group_roots: Vec::new(),
            max_group_depth: 5,
            attribute_mapping: json!({ "username": "uid" }),
        },
        &BTreeSet::new(),
    )
    .await
    .expect("plans");

    let report = apply_sweep(
        store,
        scope,
        &env,
        &sweep(vec![(
            "ldc_clash",
            with_a_clash,
            terms(&env, LdapAbsencePolicy::Deactivate),
        )]),
    )
    .await;

    assert_eq!(
        report.failures.len(),
        1,
        "expected exactly the second login to clash, got {report:?}"
    );
    assert_eq!(
        report.failures[0].0, "u-second",
        "the summed report must still name the principal that failed"
    );
    assert!(!report.everything_applied());
    assert_eq!(report.provisioned, 1, "the first of the pair still applies");
}

/// THE AUDIT ACTOR IS THE CONNECTOR. Seeded from the connector id rather than generated, so one
/// directory's whole history sits under one service actor instead of one per pass.
#[test]
fn a_connector_always_audits_under_the_same_service_actor() {
    let env = Env::system();
    let scope = Scope::new(
        ironauth_store::TenantId::generate(&env),
        ironauth_store::EnvironmentId::generate(&env),
    );
    let row = LdapConnector {
        id: LdapConnectorId::generate(&env, &scope),
        organization_id: OrganizationId::generate(&env, &scope),
        display_name: "Contoso AD".to_owned(),
        host: "ad.contoso.test".to_owned(),
        port: 636,
        tls_mode: LdapTlsMode::Ldaps,
        bind_dn: "cn=svc,dc=contoso,dc=test".to_owned(),
        bind_secret_name: "contoso-bind".to_owned(),
        user_base_dn: "ou=people,dc=contoso,dc=test".to_owned(),
        group_base_dn: String::new(),
        user_filter: "(objectClass=user)".to_owned(),
        group_filter: "(objectClass=group)".to_owned(),
        attribute_mapping: json!({ "username": "sAMAccountName" }),
        absence_policy: LdapAbsencePolicy::Delete,
        max_group_depth: 5,
        active: true,
    };

    let other = LdapConnector {
        id: LdapConnectorId::generate(&env, &scope),
        ..row.clone()
    };

    assert_eq!(
        terms_for(&row).actor,
        terms_for(&row).actor,
        "two passes over one connector must audit as one actor"
    );
    assert_ne!(
        terms_for(&row).actor,
        terms_for(&other).actor,
        "two connectors must not share an actor, or the audit log cannot tell them apart"
    );
    assert_eq!(
        terms_for(&row).policy,
        LdapAbsencePolicy::Delete,
        "the terms carry the row's own policy"
    );
}
