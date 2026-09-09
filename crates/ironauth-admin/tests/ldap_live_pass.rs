// SPDX-License-Identifier: MIT OR Apache-2.0

//! A whole pass, from stored connector row to written account, against a REAL LDAP server and a
//! real database (issue #142).
//!
//! Everything else in this series stops at one seam. This one covers the composition: `run_pass`
//! enumerates a scope, reads the connector row, opens the bind secret, binds, searches pages,
//! maps entries, diffs, translates the plan under the row's policy, and writes. No fixture can
//! stand in for it, because the thing under test is precisely that those parts are connected.
//!
//! `#[ignore]`d for the reason [`ldap_live`](../ldap_live.rs) states: a green tick meaning "did
//! not run" is worse than a missing test, and the harness already has a word for not-run. CI runs
//! it in the `ldap-live` job, against the committed fixture in `deploy/fixtures/ldap`.
//!
//! ```text
//! export IRONAUTH_LDAP_URL=ldap://<host>:<port>
//! bash scripts/with-test-db.sh cargo test -p ironauth-admin --all-features \
//!   --test ldap_live_pass -- --ignored
//! ```
//!
//! The server must hold five `inetOrgPerson` entries under `ou=People` and accept the bind DN and
//! password below, which `IRONAUTH_LDAP_BIND_DN` and `IRONAUTH_LDAP_BIND_PASSWORD` override.

#![cfg(feature = "testing")]

use ironauth_env::Env;
use ironauth_store::outbox::StaticScopes;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, LdapAbsencePolicy, LdapConnectorId, LdapTlsMode, NewLdapConnector,
    OrganizationId, Scope,
};

fn env_var(name: &str, fallback: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| fallback.to_owned())
}

/// The directory URL, or the reason the test cannot run.
fn directory_url() -> String {
    std::env::var("IRONAUTH_LDAP_URL")
        .expect("IRONAUTH_LDAP_URL must point at a live LDAP server for this test")
}

async fn seed_org(db: &TestDatabase, env: &Env, scope: Scope) -> OrganizationId {
    let id = OrganizationId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .organizations(scope)
        .create(env, &id, 0, "Directory Co", None)
        .await
        .expect("create organization");
    id
}

/// THE PRODUCTION FACTORY SUPPLIES A REAL CEILING. Every other test that touches `max_entries`
/// writes its own, so none of them observes the value the SWEEP uses: setting `MAX_ENTRIES` to
/// `usize::MAX` -- the feature switched off in production -- left the whole tree green. This
/// opens a connection the way `run_pass` does and reads the bound back off it.
#[tokio::test]
#[ignore = "requires IRONAUTH_LDAP_URL and a live directory"]
async fn the_sweeps_own_connection_carries_the_configured_ceiling() {
    use ironauth_admin::ldap_boot::{MAX_ENTRIES, StoreSourceFactory};
    use ironauth_admin::ldap_schedule::{Scheduled, SourceFactory};

    let url = directory_url();
    let (host, port) = split_url(&url);
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.control_store();
    let master = db.master_key();
    let organization = seed_org(&db, &env, scope).await;

    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .environment_secrets()
        .put(
            &env,
            &master,
            "ldap_bind_live",
            env_var("IRONAUTH_LDAP_BIND_PASSWORD", "svcpw").as_bytes(),
            None,
        )
        .await
        .expect("store the bind password");

    let id = LdapConnectorId::generate(&env, &scope);
    let mapping = serde_json::json!({ "username": "uid" });
    store
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .ldap_connectors()
        .create(
            &env,
            NewLdapConnector {
                id: &id,
                organization_id: &organization,
                display_name: "Live directory",
                host: &host,
                port,
                tls_mode: LdapTlsMode::Plaintext,
                bind_dn: &env_var("IRONAUTH_LDAP_BIND_DN", "cn=svc,dc=example,dc=test"),
                bind_secret_name: "ldap_bind_live",
                user_base_dn: &env_var("IRONAUTH_LDAP_USER_BASE", "ou=People,dc=example,dc=test"),
                group_base_dn: "",
                user_filter: "(objectClass=inetOrgPerson)",
                group_filter: "",
                attribute_mapping: &mapping,
                absence_policy: LdapAbsencePolicy::Deactivate,
                max_group_depth: 5,
            },
            None,
            None,
        )
        .await
        .expect("configure the connector");

    let connectors = store
        .scoped(scope)
        .ldap_connectors()
        .active_in_scope(10)
        .await
        .expect("read the connectors");
    let factory = StoreSourceFactory {
        store,
        scope,
        master: &master,
        connectors,
    };
    let opened = factory
        .open(&Scheduled {
            id: id.to_string(),
            previous: std::collections::BTreeSet::new(),
            inputs: ironauth_admin::ldap_boot::inputs_for(
                &store
                    .scoped(scope)
                    .ldap_connectors()
                    .get(&id)
                    .await
                    .expect("read it back"),
            ),
        })
        .await
        .expect("the sweep opens its own connection");

    assert_eq!(
        opened.ceiling(),
        MAX_ENTRIES,
        "the sweep's connection carries no ceiling from the constant, so the bound is off in \
         production while every test that writes its own value stays green"
    );
}

/// THE WHOLE PASS. Five people in a real directory become five accounts, and running it twice
/// creates nothing further.
#[tokio::test]
#[ignore = "requires IRONAUTH_LDAP_URL and a live directory"]
async fn a_pass_provisions_every_person_in_a_live_directory() {
    let url = directory_url();
    let (host, port) = split_url(&url);
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.control_store();
    let master = db.master_key();
    let organization = seed_org(&db, &env, scope).await;

    // THROUGH THE DATA PLANE, exactly as the management secrets surface does. The control role
    // may INSERT one reserved name and no other (migration 0100), so a bind secret written the
    // way this pass reads it could not be written at all. It reads it on the control plane, which
    // migration 0035 grants SELECT for.
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .environment_secrets()
        .put(
            &env,
            &master,
            "ldap_bind_live",
            env_var("IRONAUTH_LDAP_BIND_PASSWORD", "svcpw").as_bytes(),
            None,
        )
        .await
        .expect("store the bind password");

    let mapping = serde_json::json!({ "username": "uid" });
    store
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .ldap_connectors()
        .create(
            &env,
            NewLdapConnector {
                id: &LdapConnectorId::generate(&env, &scope),
                organization_id: &organization,
                display_name: "Live directory",
                host: &host,
                port,
                // The fixture's certificate is expired on purpose, so the transport under test
                // here is the plaintext one; TLS behaviour is `ldap_live`'s subject, not this
                // test's, and pretending otherwise would make this test about two things.
                tls_mode: LdapTlsMode::Plaintext,
                bind_dn: &env_var("IRONAUTH_LDAP_BIND_DN", "cn=svc,dc=example,dc=test"),
                bind_secret_name: "ldap_bind_live",
                user_base_dn: &env_var("IRONAUTH_LDAP_USER_BASE", "ou=People,dc=example,dc=test"),
                // USERS ONLY. A blank group base means no group scoping at all, which is the
                // configuration a first rollout has; pointing it at an OU that merely CONTAINS
                // groups would read as one group with no members and sync nobody.
                group_base_dn: "",
                user_filter: "(objectClass=inetOrgPerson)",
                group_filter: "",
                attribute_mapping: &mapping,
                absence_policy: LdapAbsencePolicy::Deactivate,
                max_group_depth: 5,
            },
            None,
            None,
        )
        .await
        .expect("configure the connector");

    let scopes = StaticScopes::new(vec![scope]);
    let first = ironauth_admin::ldap_boot::run_pass(store, &scopes, &env, &master, 100)
        .await
        .expect("the pass runs");

    assert_eq!(first.planned, 1, "the connector produced no plan");
    assert_eq!(first.failed, 0, "the connector failed: {first:?}");
    assert!(
        first.applied.everything_applied(),
        "{:?}",
        first.applied.failures
    );
    // HOW MANY PEOPLE THE DIRECTORY HOLDS: five for the committed fixture, and whatever the load
    // test loaded when that is driving. Parameterised because the load test previously learned
    // the count by PARSING THIS TEST'S PANIC MESSAGE -- so a pass that SUCCEEDED printed nothing
    // and the script reported it as incomplete. The script sets this and reads an exit status.
    let expected: usize = std::env::var("IRONAUTH_LDAP_EXPECT_PEOPLE")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(5);
    assert_eq!(
        first.applied.provisioned, expected,
        "the directory's {expected} people must become {expected} accounts, got {first:?}"
    );
    assert_eq!(
        first.applied.deactivated + first.applied.deleted,
        0,
        "a pass with no previous snapshot must remove nobody"
    );

    assert_eq!(
        first.snapshots_recorded, 1,
        "the pass did not record what it saw, so the next one could detect no departure"
    );

    // THE SECOND PASS IS QUIET. Everybody the directory holds is now in the snapshot, so they read
    // as retained rather than as arrivals and the change set is empty -- not five redundant
    // lookups an hour, for ever.
    let second = ironauth_admin::ldap_boot::run_pass(store, &scopes, &env, &master, 100)
        .await
        .expect("the pass runs again");
    assert_eq!(
        (
            second.applied.provisioned,
            second.applied.already_present,
            second.applied.deactivated,
            second.applied.deleted
        ),
        (0, 0, 0, 0),
        "an unchanged directory must be a quiet pass: {second:?}"
    );
    assert!(
        second.applied.everything_applied(),
        "{:?}",
        second.applied.failures
    );
}

/// `ldap://host:port` split into the two columns the connector row holds.
fn split_url(url: &str) -> (String, u16) {
    let rest = url
        .trim_start_matches("ldap://")
        .trim_start_matches("ldaps://");
    let (host, port) = rest.rsplit_once(':').expect("URL carries a port");
    (host.to_owned(), port.parse().expect("port is a number"))
}
