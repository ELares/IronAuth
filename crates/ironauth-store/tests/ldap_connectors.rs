// SPDX-License-Identifier: MIT OR Apache-2.0

//! The LDAP/AD connector configuration (issue #142).
//!
//! # What this owes
//!
//! The connector is what every later slice of #142 reads: the sync, the snapshot diff, the
//! scheduler. Two properties matter more than the CRUD:
//!
//! - a connector can only be pointed at an organization in its OWN scope, because the foreign
//!   key proves existence and not visibility -- referential integrity bypasses row-level
//!   security, and a connector aimed at another scope's organization would sync that
//!   organization's users;
//! - the closed sets (`tls_mode`, `absence_policy`) are closed at the DATABASE, so the insecure
//!   choice cannot be reached by a typo.

#![cfg(feature = "testing")]

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, LdapAbsencePolicy, LdapConnectorId, LdapTlsMode, NewLdapConnector,
    OrganizationId, Scope, StoreError,
};

async fn seed_org(db: &TestDatabase, env: &Env, scope: Scope, name: &str) -> OrganizationId {
    let id = OrganizationId::generate(env, &scope);
    let now = i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after the epoch")
            .as_micros(),
    )
    .expect("in range");
    db.control_store()
        .management()
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .organizations(scope)
        .create(env, &id, now, name, None)
        .await
        .expect("create organization");
    id
}

fn spec<'a>(
    id: &'a LdapConnectorId,
    organization: &'a OrganizationId,
    mapping: &'a serde_json::Value,
) -> NewLdapConnector<'a> {
    NewLdapConnector {
        id,
        organization_id: organization,
        display_name: "Contoso AD",
        host: "ad.contoso.test",
        port: 636,
        tls_mode: LdapTlsMode::Ldaps,
        bind_dn: "cn=svc-ironauth,ou=service,dc=contoso,dc=test",
        bind_secret_name: "contoso-ad-bind",
        user_base_dn: "ou=people,dc=contoso,dc=test",
        group_base_dn: "ou=groups,dc=contoso,dc=test",
        user_filter: "(objectClass=user)",
        group_filter: "(objectClass=group)",
        attribute_mapping: mapping,
        absence_policy: LdapAbsencePolicy::Deactivate,
        max_group_depth: 10,
    }
}

#[tokio::test]
async fn a_connector_round_trips_every_field_it_was_configured_with() {
    // EVERY FIELD, because a column that is written and read back wrong is a directory pointed
    // somewhere nobody chose -- and the two most dangerous, `tls_mode` and `absence_policy`, are
    // enums whose wrong value is silent: binding in the clear, or deleting accounts a policy
    // said to deactivate.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Contoso").await;
    let id = LdapConnectorId::generate(&env, &scope);
    let mapping = serde_json::json!({ "userName": "sAMAccountName", "email": "mail" });

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .ldap_connectors()
        .create(&env, spec(&id, &org, &mapping))
        .await
        .expect("create the connector");

    let read = db
        .control_store()
        .scoped(scope)
        .ldap_connectors()
        .get(&id)
        .await
        .expect("read it back");

    assert_eq!(read.id, id);
    assert_eq!(read.organization_id, org);
    assert_eq!(read.display_name, "Contoso AD");
    assert_eq!(read.host, "ad.contoso.test");
    assert_eq!(read.port, 636);
    assert_eq!(read.tls_mode, LdapTlsMode::Ldaps);
    assert_eq!(
        read.bind_dn,
        "cn=svc-ironauth,ou=service,dc=contoso,dc=test"
    );
    assert_eq!(read.bind_secret_name, "contoso-ad-bind");
    assert_eq!(read.user_base_dn, "ou=people,dc=contoso,dc=test");
    assert_eq!(read.group_base_dn, "ou=groups,dc=contoso,dc=test");
    assert_eq!(read.user_filter, "(objectClass=user)");
    assert_eq!(read.group_filter, "(objectClass=group)");
    assert_eq!(read.attribute_mapping, mapping);
    assert_eq!(read.absence_policy, LdapAbsencePolicy::Deactivate);
    assert_eq!(read.max_group_depth, 10);
    assert!(read.active, "a new connector is active");
}

#[tokio::test]
async fn a_connector_cannot_be_pointed_at_another_scopes_organization() {
    // THE FOREIGN KEY IS NOT ENOUGH. It proves the organization EXISTS, not that it is visible
    // here: 0205 states outright that referential integrity bypasses row-level security. Without
    // the `EXISTS` in the insert, a connector could be aimed at a neighbouring environment's
    // organization and its sync would write that organization's users.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let other_scope = db.seed_scope(&env).await;
    let theirs = seed_org(&db, &env, other_scope, "Initech").await;
    let mapping = serde_json::json!({});
    let id = LdapConnectorId::generate(&env, &scope);

    let refusal = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .ldap_connectors()
        .create(&env, spec(&id, &theirs, &mapping))
        .await
        .expect_err("a cross-scope organization must be refused");
    assert!(matches!(refusal, StoreError::NotFound), "{refusal:?}");

    // AND NOTHING WAS WRITTEN. A refusal that still inserted would leave a connector nobody can
    // read through the scoped path and the scheduler would sweep it anyway.
    let missing = db
        .control_store()
        .scoped(scope)
        .ldap_connectors()
        .get(&id)
        .await;
    assert!(matches!(missing, Err(StoreError::NotFound)), "{missing:?}");
}

#[tokio::test]
async fn an_organization_that_does_not_exist_is_refused() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let phantom = OrganizationId::generate(&env, &scope);
    let mapping = serde_json::json!({});
    let id = LdapConnectorId::generate(&env, &scope);

    let refusal = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .ldap_connectors()
        .create(&env, spec(&id, &phantom, &mapping))
        .await
        .expect_err("no such organization");
    assert!(matches!(refusal, StoreError::NotFound), "{refusal:?}");
}

#[tokio::test]
async fn the_scheduler_sees_active_connectors_across_organizations_and_not_switched_off_ones() {
    // `active_in_scope` is what a sync pass sweeps. It spans organizations deliberately -- the
    // organization is a property of each connector, not an input -- and it excludes inactive
    // ones HERE rather than in the caller, so a connector an operator switched off cannot be
    // swept by a caller that forgot to check.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let first = seed_org(&db, &env, scope, "Contoso").await;
    let second = seed_org(&db, &env, scope, "Initech").await;
    let mapping = serde_json::json!({});

    let mut ids = Vec::new();
    for org in [&first, &second] {
        let id = LdapConnectorId::generate(&env, &scope);
        db.control_store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .ldap_connectors()
            .create(&env, spec(&id, org, &mapping))
            .await
            .expect("create");
        ids.push(id);
    }

    let swept = db
        .control_store()
        .scoped(scope)
        .ldap_connectors()
        .active_in_scope(100)
        .await
        .expect("sweep");
    assert_eq!(swept.len(), 2, "both organizations' connectors are swept");

    // Switched off, and the sweep must lose it.
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .ldap_connectors()
        .set_active(&env, &ids[0], false)
        .await
        .expect("switch off");

    let swept = db
        .control_store()
        .scoped(scope)
        .ldap_connectors()
        .active_in_scope(100)
        .await
        .expect("sweep");
    assert_eq!(swept.len(), 1, "a switched-off connector is not swept");
    assert_eq!(swept[0].id, ids[1]);

    // But it is still LISTED for its organization, because an operator has to be able to see and
    // re-enable what they turned off.
    let listed = db
        .control_store()
        .scoped(scope)
        .ldap_connectors()
        .list_for_org(&first, 100)
        .await
        .expect("list");
    assert_eq!(
        listed.len(),
        1,
        "the switched-off connector is still listed"
    );
    assert!(!listed[0].active);
}

#[tokio::test]
async fn the_closed_sets_are_closed_at_the_database() {
    // #142 requires LDAPS or StartTLS by default with an explicit flag for plaintext. The enum
    // keeps a caller from constructing a fourth mode; this asserts the COLUMN does too, so a
    // value reaching the table by any other route -- a migration, a fixture, a future handler
    // binding a string -- is refused rather than read back as something the code must guess at.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Contoso").await;
    let id = LdapConnectorId::generate(&env, &scope);
    let mapping = serde_json::json!({});
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .ldap_connectors()
        .create(&env, spec(&id, &org, &mapping))
        .await
        .expect("create");

    for (column, value) in [("tls_mode", "none"), ("absence_policy", "archive")] {
        let refusal = sqlx::query(&format!(
            "UPDATE ldap_connectors SET {column} = $1 WHERE id = $2"
        ))
        .bind(value)
        .bind(id.to_string())
        .execute(db.owner_pool())
        .await;
        assert!(
            refusal.is_err(),
            "the database accepted {column} = {value}, so the set is not closed"
        );
    }
}

#[tokio::test]
async fn a_tls_mode_this_build_does_not_know_is_an_error_and_not_a_default() {
    // THE SKEW A FUTURE MIGRATION CREATES. Today the CHECK constraint makes an unknown
    // `tls_mode` unwritable, so the decode arm looks unreachable -- and a mutation replacing it
    // with `unwrap_or(Ldaps)` survived every other test here.
    //
    // It becomes reachable the moment a migration widens that CHECK ahead of the binary that
    // reads it, which is the ordinary shape of a rolling upgrade: schema first, then the nodes.
    // Defaulting an unrecognised transport to LDAPS would then report a connection as encrypted
    // BECAUSE this build had never heard of the mode it was actually using -- the failure
    // direction that matters, since the alternative is a loud error nobody can miss.
    //
    // Simulated the way that upgrade does it: widen the constraint, write the row, read it back.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Contoso").await;
    let id = LdapConnectorId::generate(&env, &scope);
    let mapping = serde_json::json!({});
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .ldap_connectors()
        .create(&env, spec(&id, &org, &mapping))
        .await
        .expect("create");

    sqlx::query(
        "ALTER TABLE ldap_connectors DROP CONSTRAINT ldap_connectors_tls_mode_known, \
         ADD CONSTRAINT ldap_connectors_tls_mode_known \
             CHECK (tls_mode IN ('ldaps', 'starttls', 'plaintext', 'quic-ldap'))",
    )
    .execute(db.owner_pool())
    .await
    .expect("widen the constraint the way a later migration would");
    sqlx::query("UPDATE ldap_connectors SET tls_mode = 'quic-ldap' WHERE id = $1")
        .bind(id.to_string())
        .execute(db.owner_pool())
        .await
        .expect("write the mode this build has never heard of");

    let outcome = db
        .control_store()
        .scoped(scope)
        .ldap_connectors()
        .get(&id)
        .await;
    let error = outcome.expect_err("an unknown tls_mode must not decode to anything");
    assert!(
        matches!(error, StoreError::Database(_)),
        "it must surface as a decode failure rather than a silent default: {error:?}"
    );
}
