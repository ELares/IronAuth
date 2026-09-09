// SPDX-License-Identifier: MIT OR Apache-2.0

//! Applying what a sweep planned (issue #142), over a real database and no directory.
//!
//! [`apply_sweep`] takes a sweep report rather than opening connections, which is what makes the
//! applied-versus-planned properties testable at all: a live LDAP server can be pointed at a
//! fixture, but it cannot be made to produce a plan for a connector whose policy went missing, or
//! two connectors with opposite policies in one pass.

#![cfg(feature = "testing")]

use std::collections::{BTreeMap, BTreeSet};

use ironauth_admin::ldap_boot::{
    ApplyTerms, PassReport, ScopeSweep, apply_sweep, fold_scope, terms_for,
};
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

    assert!(
        report.total.everything_applied(),
        "{:?}",
        report.total.failures
    );
    assert_eq!(report.total.provisioned, 2);
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
    assert_eq!(
        again.total.provisioned, 0,
        "the second pass created them again"
    );
    assert_eq!(
        again.total.already_present, 2,
        "the second pass did not recognise its own accounts: {again:?}"
    );
    assert!(
        again.total.everything_applied(),
        "{:?}",
        again.total.failures
    );
}

/// THE SAME DEPARTURE, TWO PASSES. A removal that is not idempotent turns into a permanent
/// per-principal failure and a daemon that logs "needs attention" on every tick with nothing an
/// operator can clear. The snapshot narrows after a successful removal, so a real pass stops
/// re-deriving the departure -- but a snapshot that failed to record, or a directory that keeps
/// re-listing somebody, puts the same change set in front of the applier again.
#[tokio::test]
async fn the_same_departure_on_two_passes_needs_attention_only_never() {
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
            planned(&[("leaver", "u-leaver"), ("keeper", "u-keeper")], &[]).await,
            terms(&env, LdapAbsencePolicy::Deactivate),
        )]),
    )
    .await;

    let departing =
        |()| async { planned(&[("keeper", "u-keeper")], &["u-leaver", "u-keeper"]).await };

    let first = apply_sweep(
        store,
        scope,
        &env,
        &sweep(vec![(
            "ldc_one",
            departing(()).await,
            terms(&env, LdapAbsencePolicy::Deactivate),
        )]),
    )
    .await;
    assert_eq!(first.total.deactivated, 1, "{first:?}");
    assert!(
        first.total.everything_applied(),
        "{:?}",
        first.total.failures
    );

    let second = apply_sweep(
        store,
        scope,
        &env,
        &sweep(vec![(
            "ldc_one",
            departing(()).await,
            terms(&env, LdapAbsencePolicy::Deactivate),
        )]),
    )
    .await;
    assert!(
        second.total.everything_applied(),
        "the second pass over the same departure reported failures {:?}",
        second.total.failures
    );
    assert_eq!(second.total.already_removed, 1, "{second:?}");
    assert_eq!(second.total.deactivated, 0);
    assert_eq!(
        state_of(store, scope, "u-leaver").await,
        Some(UserState::Disabled)
    );
    assert_eq!(
        state_of(store, scope, "u-keeper").await,
        Some(UserState::Active)
    );
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
        report.total.everything_applied(),
        "a departure with no account was reported as a failure: {:?}",
        report.total.failures
    );
    assert_eq!(
        report.total.already_absent, 1,
        "the absent departure was not counted: {report:?}"
    );
    assert_eq!(report.total.deactivated, 0);
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

    assert!(
        report.total.everything_applied(),
        "{:?}",
        report.total.failures
    );
    assert_eq!(
        report.total.deactivated, 1,
        "exactly one connector deactivates"
    );
    assert_eq!(report.total.deleted, 1, "exactly one connector deletes");
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

    assert_eq!(report.total.deleted, 0);
    assert_eq!(report.total.deactivated, 0);
    assert!(
        report.total.everything_applied(),
        "{:?}",
        report.total.failures
    );
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

    assert_eq!(
        report.total.provisioned, 0,
        "no arrival may be written either"
    );
    assert_eq!(report.total.deleted, 0);
    assert_eq!(report.total.deactivated, 0);
    assert!(
        report.total.everything_applied(),
        "{:?}",
        report.total.failures
    );
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

    assert!(
        report.total.everything_applied(),
        "{:?}",
        report.total.failures
    );
    assert_eq!(
        report.total.provisioned, 1,
        "the reachable connector's arrival is the whole point of the isolation"
    );
    // EVERY OTHER COUNTER IS ZERO. Asserting only the provision would let an outcome with no plan
    // contribute to the tally -- an unreachable directory reporting activity it did not have.
    assert_eq!(
        (
            report.total.already_present,
            report.total.deactivated,
            report.total.deleted,
            report.total.already_absent
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
        report.total.failures.len(),
        1,
        "expected exactly the second login to clash, got {report:?}"
    );
    assert_eq!(
        report.total.failures[0].0, "u-second",
        "the summed report must still name the principal that failed"
    );
    assert!(!report.total.everything_applied());
    assert_eq!(
        report.total.provisioned, 1,
        "the first of the pair still applies"
    );
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
    // BOTH DIRECTIONS. A single fixture asserted against its own constant cannot fail when the
    // bridge is hardcoded to THAT constant, and the constant this fixture holds is the
    // irreversible one -- so a `terms_for` that always answered Delete would have passed.
    let deactivating = LdapConnector {
        id: LdapConnectorId::generate(&env, &scope),
        absence_policy: LdapAbsencePolicy::Deactivate,
        ..row.clone()
    };
    assert_eq!(
        terms_for(&row).policy,
        LdapAbsencePolicy::Delete,
        "the terms carry the row's own policy"
    );
    assert_eq!(
        terms_for(&deactivating).policy,
        LdapAbsencePolicy::Deactivate,
        "a deactivating row's departures would be DELETED, which is not reversible"
    );
}

/// THE SEEDED ACTOR REACHES THE WRITE. `terms_for` producing a stable actor proves nothing about
/// the audit log if `apply_sweep` then hands `execute` some other actor: replacing `terms.actor`
/// with a freshly generated one -- the exact regression the design note names -- left every
/// assertion green. This reads the audit row.
#[tokio::test]
async fn the_audit_row_names_the_connector_that_provisioned() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.control_store();

    let connector = LdapConnectorId::generate(&env, &scope);
    let expected = ServiceId::from_seed_bytes(connector.unique_bytes()).to_string();

    apply_sweep(
        store,
        scope,
        &env,
        &ScopeSweep {
            report: SweepReport {
                runs: vec![(
                    connector.to_string(),
                    Outcome::Planned(Box::new(planned(&[("audited", "u-audited")], &[]).await)),
                )],
            },
            terms: BTreeMap::from([(
                connector.to_string(),
                ApplyTerms {
                    policy: LdapAbsencePolicy::Deactivate,
                    actor: ActorRef::service(ServiceId::from_seed_bytes(connector.unique_bytes())),
                },
            )]),
        },
    )
    .await;

    let actors: Vec<(String, String)> = sqlx::query_as(
        "SELECT actor_kind::text, actor_id::text FROM audit_log          WHERE tenant_id = $1 AND environment_id = $2 AND action = 'user.create'",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_all(db.owner_pool())
    .await
    .expect("read the audit log");

    assert_eq!(
        actors.len(),
        1,
        "expected exactly the one create: {actors:?}"
    );
    assert_eq!(actors[0].0, "service", "a sweep is not a human");
    assert_eq!(
        actors[0].1, expected,
        "the audit row does not name the connector, so \"what has this directory done to my \
         users\" has no answer"
    );
}

/// TWO CONNECTORS CONTRIBUTING TO ONE COUNTER. Every other fixture gives each counter a single
/// contributor, so a fold that ASSIGNS rather than adds reports the last connector's numbers and
/// passes. With failures that is the dangerous shape: a connector failing on everybody followed
/// by a clean one reads as a clean pass, and the daemon logs it as one.
#[tokio::test]
async fn a_pass_sums_two_connectors_rather_than_reporting_the_last() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.control_store();

    // Each connector brings two arrivals and one login that clashes with its own first arrival.
    let report = apply_sweep(
        store,
        scope,
        &env,
        &sweep(vec![
            (
                "ldc_a",
                clashing_plan("a").await,
                terms(&env, LdapAbsencePolicy::Deactivate),
            ),
            (
                "ldc_b",
                clashing_plan("b").await,
                terms(&env, LdapAbsencePolicy::Deactivate),
            ),
        ]),
    )
    .await;

    assert_eq!(
        report.total.provisioned, 4,
        "two connectors provisioning two each must sum to four: {report:?}"
    );
    assert_eq!(
        report.total.failures.len(),
        2,
        "each connector's clash must survive the fold: {report:?}"
    );
    let named: BTreeSet<&str> = report
        .total
        .failures
        .iter()
        .map(|(id, _)| id.as_str())
        .collect();
    assert_eq!(
        named,
        BTreeSet::from(["a-3-clash", "b-3-clash"]),
        "a fold that assigned rather than added would carry only the last connector's failure"
    );
}

/// Three principals under one prefix, so two connectors' fixtures never collide.
async fn three_people(prefix: &str) -> SyncPlan {
    planned(
        &[
            (&format!("{prefix}stay"), &format!("{prefix}-stay")),
            (&format!("{prefix}gone"), &format!("{prefix}-gone")),
            (&format!("{prefix}left"), &format!("{prefix}-left")),
        ],
        &[],
    )
    .await
}

/// The same directory with `-left` already departed, so a later pass sees them already removed.
async fn without_left(prefix: &str) -> SyncPlan {
    planned(
        &[
            (&format!("{prefix}stay"), &format!("{prefix}-stay")),
            (&format!("{prefix}gone"), &format!("{prefix}-gone")),
        ],
        &[
            &format!("{prefix}-stay"),
            &format!("{prefix}-gone"),
            &format!("{prefix}-left"),
        ],
    )
    .await
}

/// One connector's four removal outcomes at once: `-stay` reads as an ARRIVAL who already has an
/// account (the shape every pass has today, with no snapshot to remember them by), `-gone` leaves
/// now, `-left` left last pass, `-ghost` was in the snapshot and never had an account.
async fn all_four_outcomes(prefix: &str) -> SyncPlan {
    planned(
        &[(&format!("{prefix}stay"), &format!("{prefix}-stay"))],
        &[
            &format!("{prefix}-gone"),
            &format!("{prefix}-left"),
            &format!("{prefix}-ghost"),
        ],
    )
    .await
}

/// A two-connector sweep built from one plan-maker, both connectors under `policy`.
async fn both_connectors<F, Fut>(make: F, policy: LdapAbsencePolicy, env: &Env) -> ScopeSweep
where
    F: Fn(&'static str) -> Fut,
    Fut: std::future::Future<Output = SyncPlan>,
{
    sweep(vec![
        ("ldc_a", make("a").await, terms(env, policy)),
        ("ldc_b", make("b").await, terms(env, policy)),
    ])
}

/// EVERY COUNTER SUMS, not just the two the clash fixture reaches. A fold that ASSIGNS reports
/// the last connector's number for whichever field it broke, and each field needs two nonzero
/// contributors to tell the two apart. One sweep gives each connector all four removal outcomes.
#[tokio::test]
async fn every_removal_counter_sums_across_two_connectors() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.control_store();
    let soft = LdapAbsencePolicy::Deactivate;

    apply_sweep(
        store,
        scope,
        &env,
        &both_connectors(three_people, soft, &env).await,
    )
    .await;
    apply_sweep(
        store,
        scope,
        &env,
        &both_connectors(without_left, soft, &env).await,
    )
    .await;
    let report = apply_sweep(
        store,
        scope,
        &env,
        &both_connectors(all_four_outcomes, soft, &env).await,
    )
    .await;

    assert!(
        report.total.everything_applied(),
        "{:?}",
        report.total.failures
    );
    assert_eq!(
        (
            report.total.already_present,
            report.total.deactivated,
            report.total.already_removed,
            report.total.already_absent
        ),
        (2, 2, 2, 2),
        "each counter needs both connectors' contribution: {report:?}"
    );
}

/// AND THE IRREVERSIBLE COUNTER. `deleted` is the one field the fixture above cannot reach,
/// because a deactivating connector never sets it.
#[tokio::test]
async fn two_deleting_connectors_sum_their_deletions() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.control_store();
    let hard = LdapAbsencePolicy::Delete;

    apply_sweep(
        store,
        scope,
        &env,
        &both_connectors(three_people, hard, &env).await,
    )
    .await;
    let report = apply_sweep(
        store,
        scope,
        &env,
        &both_connectors(without_left, hard, &env).await,
    )
    .await;

    assert!(
        report.total.everything_applied(),
        "{:?}",
        report.total.failures
    );
    assert_eq!(
        report.total.deleted, 2,
        "both connectors' deletions must sum: {report:?}"
    );
    assert_eq!(state_of(store, scope, "a-left").await, None);
    assert_eq!(state_of(store, scope, "b-left").await, None);
}

/// Two arrivals and a third whose login collides with the first, all under one prefix so two of
/// these plans do not collide with each other.
async fn clashing_plan(prefix: &str) -> SyncPlan {
    let fake = Fake {
        people: vec![
            person(&format!("{prefix}one"), &format!("{prefix}-1-first")),
            person(&format!("{prefix}two"), &format!("{prefix}-2-second")),
            DirectoryEntry::new(
                format!("uid={prefix}one,ou=Other,dc=example,dc=test"),
                vec![
                    ("uid".to_owned(), vec![format!("{prefix}one")]),
                    ("entryUUID".to_owned(), vec![format!("{prefix}-3-clash")]),
                ],
            ),
        ],
    };
    plan(
        &fake,
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
    .expect("plans")
}

/// THE PASS'S OWN BODY APPLIES. `run_pass` reads scopes and opens directories, so the only thing
/// that used to observe it applying anything was a live-directory test CI does not run -- deleting
/// the apply call left every test in the repository green. [`fold_scope`] is everything the pass
/// does with a sweep, and it needs no directory.
#[tokio::test]
async fn the_pass_body_counts_and_applies_the_sweep_it_is_given() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.control_store();

    let mut mixed = sweep(vec![(
        "ldc_ok",
        planned(&[("folded", "u-folded")], &[]).await,
        terms(&env, LdapAbsencePolicy::Deactivate),
    )]);
    mixed.report.runs.push((
        "ldc_down".to_owned(),
        Outcome::Unreachable("connection refused".to_owned()),
    ));

    let mut report = PassReport::default();
    fold_scope(store, scope, &env, &db.master_key(), &mixed, &mut report).await;

    assert_eq!(report.planned, 1, "the plan was not counted");
    assert_eq!(
        report.failed, 1,
        "the unreachable connector was not counted"
    );
    assert_eq!(
        report.applied.provisioned, 1,
        "the pass counted the plan and did not apply it: {report:?}"
    );
    assert_eq!(
        state_of(store, scope, "u-folded").await,
        Some(UserState::Active)
    );
}

/// AND THE PASS REPEATS. `run_pass` sweeps against an empty previous snapshot every tick, so the
/// second pass over an unchanged directory is the ordinary case; it must add nothing and report
/// nothing needing attention.
#[tokio::test]
async fn a_second_pass_over_the_same_sweep_reports_a_quiet_run() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.control_store();

    let mut first = PassReport::default();
    fold_scope(
        store,
        scope,
        &env,
        &db.master_key(),
        &sweep(vec![(
            "ldc_ok",
            planned(&[("steady", "u-steady")], &[]).await,
            terms(&env, LdapAbsencePolicy::Deactivate),
        )]),
        &mut first,
    )
    .await;
    assert_eq!(first.applied.provisioned, 1);

    let mut second = PassReport::default();
    fold_scope(
        store,
        scope,
        &env,
        &db.master_key(),
        &sweep(vec![(
            "ldc_ok",
            planned(&[("steady", "u-steady")], &[]).await,
            terms(&env, LdapAbsencePolicy::Deactivate),
        )]),
        &mut second,
    )
    .await;

    assert_eq!(second.applied.provisioned, 0);
    assert_eq!(second.applied.already_present, 1);
    assert!(
        second.applied.everything_applied(),
        "an hourly tick over an unchanged directory must not need attention: {:?}",
        second.applied.failures
    );
}
