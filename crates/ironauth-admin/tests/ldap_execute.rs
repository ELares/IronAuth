// SPDX-License-Identifier: MIT OR Apache-2.0

//! Carrying out a change set against a real database (issue #142).
//!
//! The acceptance criterion these cover is "provisioning, deactivation and deletion are applied
//! through the user lifecycle", plus the two properties an hourly job cannot ship without: every
//! operation repeats without harm, and one bad row does not abandon the rest.

#![cfg(feature = "testing")]

use std::collections::{BTreeMap, BTreeSet};

use ironauth_admin::ldap_changeset::{Change, ChangeSet};
use ironauth_admin::ldap_execute::{execute, plan_and_execute};
use ironauth_admin::ldap_groups::{GroupSource, Member};
use ironauth_admin::ldap_mapping::DirectoryEntry;
use ironauth_admin::ldap_sync::{EntrySource, SyncInputs, SyncPlan, plan};
use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    AuthorizationCodeId, ClientId, CorrelationId, GrantId, IssueCode, LdapAbsencePolicy,
    NewRefreshFamily, NewSession, RefreshFamilyId, RefreshTokenId, Scope, SessionId, Store,
    StoredClientId, UserAdminRecord, UserState, refresh_token_digest,
};
use serde_json::json;

fn provision(stable: &str, username: &str) -> Change {
    Change::Provision {
        stable_id: stable.to_owned(),
        username: username.to_owned(),
    }
}

fn set(changes: Vec<Change>) -> ChangeSet {
    ChangeSet {
        changes,
        withheld: None,
    }
}

async fn look_up(store: &Store, scope: Scope, stable: &str) -> Option<UserAdminRecord> {
    store
        .scoped(scope)
        .users()
        .by_external_id(stable)
        .await
        .expect("read by external id")
}

/// THE CREATE. A principal the run has never seen becomes an account carrying the directory's
/// stable identifier, under the directory's login.
#[tokio::test]
async fn provisioning_creates_an_account_the_next_pass_can_find() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.control_store();
    let actor = db.test_actor(&env);

    let report = execute(
        store,
        scope,
        &env,
        actor,
        &set(vec![provision("u-ada", "ada")]),
    )
    .await;

    assert!(
        report.everything_applied(),
        "failures: {:?}",
        report.failures
    );
    assert_eq!(report.provisioned, 1);
    assert_eq!(report.already_present, 0);

    let created = look_up(store, scope, "u-ada")
        .await
        .expect("account exists");
    assert_eq!(
        created.identifier, "ada",
        "the directory's login is the login"
    );
    assert_eq!(
        created.external_id.as_deref(),
        Some("u-ada"),
        "without the link the next pass provisions a duplicate every hour"
    );
    assert_eq!(created.state, UserState::Active);
}

/// THE REPEAT. The sweep runs hourly and the snapshot it diffs against can be lost; a second run
/// over the same change set must not create a second account or report a failure.
#[tokio::test]
async fn a_second_run_over_the_same_change_set_changes_nothing() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.control_store();
    let actor = db.test_actor(&env);
    let changes = set(vec![provision("u-grace", "grace")]);

    let first = execute(store, scope, &env, actor, &changes).await;
    let created = look_up(store, scope, "u-grace").await.expect("created");

    let second = execute(store, scope, &env, actor, &changes).await;

    assert_eq!(first.provisioned, 1);
    assert_eq!(second.provisioned, 0, "a repeat must not create");
    assert_eq!(second.already_present, 1);
    assert!(second.everything_applied(), "{:?}", second.failures);
    assert_eq!(
        second.changed(),
        0,
        "an unchanged directory must read as a quiet pass, not a churning one"
    );

    let after = look_up(store, scope, "u-grace").await.expect("still there");
    assert_eq!(
        after.id, created.id,
        "the second run must find the same account, not shadow it with another"
    );
}

/// THE REVERSIBLE REMOVAL. `Deactivate` has to reach a state that cannot authenticate; asserting
/// merely "not Active" would pass on any of six.
#[tokio::test]
async fn deactivation_disables_the_account_it_names() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.control_store();
    let actor = db.test_actor(&env);

    execute(
        store,
        scope,
        &env,
        actor,
        &set(vec![provision("u-alan", "alan"), provision("u-kay", "kay")]),
    )
    .await;

    let report = execute(
        store,
        scope,
        &env,
        actor,
        &set(vec![Change::Deactivate {
            stable_id: "u-alan".to_owned(),
        }]),
    )
    .await;

    assert!(report.everything_applied(), "{:?}", report.failures);
    assert_eq!(report.deactivated, 1);

    let gone = look_up(store, scope, "u-alan").await.expect("row survives");
    assert_eq!(
        gone.state,
        UserState::Disabled,
        "a departure is disabled, not blocked: blocked would read back as an administrator's decision"
    );
    assert_eq!(
        look_up(store, scope, "u-kay")
            .await
            .expect("untouched")
            .state,
        UserState::Active,
        "deactivating one principal must not reach the other"
    );
}

/// THE IRREVERSIBLE REMOVAL, and the same containment check.
#[tokio::test]
async fn deletion_removes_the_account_it_names_and_only_that_one() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.control_store();
    let actor = db.test_actor(&env);

    execute(
        store,
        scope,
        &env,
        actor,
        &set(vec![
            provision("u-edsger", "edsger"),
            provision("u-barbara", "barbara"),
        ]),
    )
    .await;

    let report = execute(
        store,
        scope,
        &env,
        actor,
        &set(vec![Change::Delete {
            stable_id: "u-edsger".to_owned(),
        }]),
    )
    .await;

    assert!(report.everything_applied(), "{:?}", report.failures);
    assert_eq!(report.deleted, 1);
    assert!(
        look_up(store, scope, "u-edsger").await.is_none(),
        "delete must remove the account"
    );
    assert!(
        look_up(store, scope, "u-barbara").await.is_some(),
        "deleting one principal must not reach the other"
    );
}

/// THE MISSING TARGET. A removal for somebody who has no account is the ordinary state of a
/// re-run, and raising on it would leave every later pass failing on the same row.
#[tokio::test]
async fn removing_a_principal_with_no_account_is_a_no_op() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.control_store();
    let actor = db.test_actor(&env);

    let report = execute(
        store,
        scope,
        &env,
        actor,
        &set(vec![
            Change::Deactivate {
                stable_id: "u-never".to_owned(),
            },
            Change::Delete {
                stable_id: "u-also-never".to_owned(),
            },
        ]),
    )
    .await;

    assert!(
        report.everything_applied(),
        "an absent principal is not a fault: {:?}",
        report.failures
    );
    assert_eq!(report.already_absent, 2);
    assert_eq!(report.deactivated, 0);
    assert_eq!(report.deleted, 0);
}

/// THE BAD ROW. Two directory principals mapping to one login is a real directory state, and the
/// second create fails on the login's uniqueness. The run must record it against its stable id
/// and carry on: without this, one such pair leaves the whole directory unprovisioned.
#[tokio::test]
async fn one_failing_change_does_not_abandon_the_others() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.control_store();
    let actor = db.test_actor(&env);

    let report = execute(
        store,
        scope,
        &env,
        actor,
        &set(vec![
            provision("u-1-first", "shared-login"),
            provision("u-2-clash", "shared-login"),
            provision("u-3-after", "distinct-login"),
        ]),
    )
    .await;

    assert_eq!(
        report.failures.len(),
        1,
        "expected exactly the clash to fail, got {:?}",
        report.failures
    );
    assert_eq!(
        report.failures[0].0, "u-2-clash",
        "a failure has to name the principal it belongs to, or it cannot be chased"
    );
    assert!(!report.everything_applied());
    assert_eq!(report.provisioned, 2);
    assert!(
        look_up(store, scope, "u-3-after").await.is_some(),
        "the change AFTER the failure is the one that proves the run continued"
    );
    assert!(
        look_up(store, scope, "u-2-clash").await.is_none(),
        "the failed change must not leave a half-written account"
    );
}

// ---------------------------------------------------------------------------
// The hard kill: what "deactivated" has to mean for somebody who has left.
// ---------------------------------------------------------------------------

/// A far-future expiry, so anything that stops resolving stopped because it was revoked.
const FAR_FUTURE_MICROS: i64 = 4_102_444_800_000_000;

/// A session for `subject`, and an `offline_access` refresh family rooted in a grant that carries
/// it. Offline deliberately: a session-bound family dies with the session under EITHER flag, so
/// only the offline family can tell a hard kill from a soft one.
async fn offline_family_for(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    subject: &str,
) -> RefreshFamilyId {
    let session = SessionId::generate(env, &scope);
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .sessions()
        .rotate(
            env,
            &session,
            None,
            NewSession {
                impersonation: None,
                subject,
                auth_methods: "pwd",
                auth_time_micros: 0,
                idle_expires_micros: FAR_FUTURE_MICROS,
                absolute_expires_micros: FAR_FUTURE_MICROS,
                user_agent: None,
                peer_ip: None,
            },
        )
        .await
        .expect("rotate session");

    let grant = GrantId::generate(env, &scope);
    let session_text = session.to_string();
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .authorization()
        .issue(
            env,
            IssueCode {
                code_id: &AuthorizationCodeId::generate(env, &scope),
                grant_id: &grant,
                client_id: StoredClientId::Registered(&ClientId::generate(env, &scope)),
                redirect_uri: "https://client.test/cb",
                browserless: false,
                nonce: None,
                code_challenge: None,
                code_challenge_method: None,
                subject,
                oauth_scope: Some("openid"),
                auth_methods: "pwd",
                auth_time_micros: None,
                session_ref: Some(&session_text),
                org_id: None,
                consent_ref: None,
                claims_request: None,
                granted_resources: &[],
                dpop_jkt: None,
                expires_at_micros: FAR_FUTURE_MICROS,
                created_at_micros: 0,
            },
        )
        .await
        .expect("issue code");

    let family = RefreshFamilyId::generate(env, &scope);
    let jti = RefreshTokenId::generate(env, &scope);
    let digest = refresh_token_digest(&format!("ira_rt_{jti}~seed"));
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .refresh()
        .issue(
            env,
            NewRefreshFamily {
                family_id: &family,
                token_jti: &jti,
                token_digest: &digest,
                grant_id: &grant,
                subject,
                client_id: "cli_ldap_sweep",
                scope: Some("openid"),
                auth_methods: "pwd",
                auth_time_unix_micros: None,
                offline: true,
                created_at_unix_micros: 0,
                idle_expires_at_unix_micros: FAR_FUTURE_MICROS,
                absolute_expires_at_unix_micros: FAR_FUTURE_MICROS,
                dpop_jkt: None,
            },
        )
        .await
        .expect("open offline family");
    family
}

async fn family_revoked(db: &TestDatabase, scope: Scope, family: &RefreshFamilyId) -> bool {
    db.store()
        .scoped(scope)
        .refresh_family_fleet()
        .get(family)
        .await
        .expect("read family")
        .expect("family exists")
        .revoked_at_unix_micros
        .is_some()
}

/// THE POINT OF DEACTIVATING AT ALL. An `offline_access` refresh token SURVIVES an ordinary state
/// change (issue #21's offline-survives-logout semantic), so a departure applied without the hard
/// kill leaves the leaver holding a working credential until it expires -- which is the exact
/// window this subsystem exists to close. Only the offline family can distinguish the two flags:
/// a session-bound family dies under either.
#[tokio::test]
async fn a_departure_ends_the_offline_refresh_families_too() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.control_store();
    let actor = db.test_actor(&env);

    execute(
        store,
        scope,
        &env,
        actor,
        &set(vec![
            provision("u-leaver", "leaver"),
            provision("u-stayer", "stayer"),
        ]),
    )
    .await;
    let leaver = look_up(store, scope, "u-leaver")
        .await
        .expect("provisioned");
    let stayer = look_up(store, scope, "u-stayer")
        .await
        .expect("provisioned");

    let doomed = offline_family_for(&db, &env, scope, &leaver.id.to_string()).await;
    let bystander = offline_family_for(&db, &env, scope, &stayer.id.to_string()).await;
    assert!(
        !family_revoked(&db, scope, &doomed).await,
        "the family must start live, or the assertion below cannot fail"
    );

    let report = execute(
        store,
        scope,
        &env,
        actor,
        &set(vec![Change::Deactivate {
            stable_id: "u-leaver".to_owned(),
        }]),
    )
    .await;
    assert!(report.everything_applied(), "{:?}", report.failures);

    assert!(
        family_revoked(&db, scope, &doomed).await,
        "a departed principal kept a working offline_access refresh token"
    );
    assert!(
        !family_revoked(&db, scope, &bystander).await,
        "the removal reached somebody the change set did not name"
    );
}

/// THE SAME OBLIGATION UNDER THE OTHER POLICY. Delete takes the row away; the credential rooted
/// in it has to go too, and by the same flag.
#[tokio::test]
async fn a_deletion_ends_the_offline_refresh_families_too() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.control_store();
    let actor = db.test_actor(&env);

    execute(
        store,
        scope,
        &env,
        actor,
        &set(vec![provision("u-purged", "purged")]),
    )
    .await;
    let purged = look_up(store, scope, "u-purged")
        .await
        .expect("provisioned");
    let doomed = offline_family_for(&db, &env, scope, &purged.id.to_string()).await;
    assert!(
        !family_revoked(&db, scope, &doomed).await,
        "must start live"
    );

    let report = execute(
        store,
        scope,
        &env,
        actor,
        &set(vec![Change::Delete {
            stable_id: "u-purged".to_owned(),
        }]),
    )
    .await;
    assert!(report.everything_applied(), "{:?}", report.failures);
    assert!(
        family_revoked(&db, scope, &doomed).await,
        "a deleted principal kept a working offline_access refresh token"
    );
}

// ---------------------------------------------------------------------------
// The dry-run contract, end to end.
// ---------------------------------------------------------------------------

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
        &previous.iter().map(|s| (*s).to_owned()).collect(),
    )
    .await
    .expect("plans")
}

/// THE CONTRACT #142 asks for in words: what a dry run reports is what a real run does. Not
/// "the two agree" -- the same value, and the database afterwards holds exactly the accounts that
/// value named, with nothing extra.
#[tokio::test]
async fn what_the_dry_run_reports_is_what_the_real_run_applies() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.control_store();
    let actor = db.test_actor(&env);

    // Somebody arrives, somebody leaves, somebody stays.
    execute(
        store,
        scope,
        &env,
        actor,
        &set(vec![
            provision("u-stays", "stays"),
            provision("u-leaves", "leaves"),
        ]),
    )
    .await;

    let sync = planned(
        &[("stays", "u-stays"), ("joins", "u-joins")],
        &["u-stays", "u-leaves"],
    )
    .await;

    // The dry run: what WOULD happen, computed and shown to an operator.
    let dry = ChangeSet::from_plan(&sync, LdapAbsencePolicy::Deactivate);
    assert!(
        !dry.is_empty(),
        "a dry run over an arrival and a departure must not report an empty change set"
    );
    let before: BTreeMap<String, UserState> =
        states(store, scope, &["u-stays", "u-leaves", "u-joins"]).await;
    assert_eq!(
        before.get("u-joins"),
        None,
        "the arrival must not already exist, or the provision assertion below is vacuous"
    );

    // The real run.
    let (applied, report) = plan_and_execute(
        store,
        scope,
        &env,
        actor,
        &sync,
        LdapAbsencePolicy::Deactivate,
    )
    .await;

    assert_eq!(
        applied.changes, dry.changes,
        "the operator was shown a different set of operations from the one that ran"
    );
    assert!(report.everything_applied(), "{:?}", report.failures);

    assert_eq!(applied.provisions(), BTreeSet::from(["u-joins"]));
    assert_eq!(applied.removals(), BTreeSet::from(["u-leaves"]));

    let after = states(store, scope, &["u-stays", "u-leaves", "u-joins"]).await;
    assert_eq!(
        after.get("u-joins"),
        Some(&UserState::Active),
        "the named arrival was not created"
    );
    assert_eq!(
        after.get("u-leaves"),
        Some(&UserState::Disabled),
        "the named departure was not deactivated"
    );
    assert_eq!(
        after.get("u-stays"),
        Some(&UserState::Active),
        "somebody the change set did not name was touched anyway"
    );
}

async fn states(store: &Store, scope: Scope, ids: &[&str]) -> BTreeMap<String, UserState> {
    let mut found = BTreeMap::new();
    for id in ids {
        if let Some(record) = look_up(store, scope, id).await {
            found.insert((*id).to_owned(), record.state);
        }
    }
    found
}
