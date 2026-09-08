// SPDX-License-Identifier: MIT OR Apache-2.0

//! The LDAP/AD connector configuration (issue #142).
//!
//! # What this owes
//!
//! The connector is what every later slice of #142 reads: the sync, the snapshot diff, the
//! scheduler. Two properties matter more than the CRUD:
//!
//! - a connector can only be pointed at an organization that is in its own scope, exists, and
//!   has not been deleted. Three different mechanisms enforce those: the scope-typed
//!   `OrganizationId` guard in `create`, the foreign key, and the `AND deleted_at IS NULL`
//!   conjunct in the insert's `EXISTS`. Only the last of the three has no other backstop, since
//!   the foreign key still matches a soft-deleted row -- referential integrity bypasses
//!   row-level security, as 0205 says;
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
        port: 389,
        // DELIBERATELY NOT THE COLUMN DEFAULTS. `tls_mode`, `absence_policy` and
        // `max_group_depth` all default in 0212 to 'ldaps', 'deactivate' and 10, so a fixture
        // carrying those values makes every round-trip assertion on them unable to tell a value
        // that was written from a value the column supplied. Four mutations that dropped the
        // caller's choice on the floor passed against the first version of this file.
        tls_mode: LdapTlsMode::StartTls,
        bind_dn: "cn=svc-ironauth,ou=service,dc=contoso,dc=test",
        bind_secret_name: "contoso-ad-bind",
        user_base_dn: "ou=people,dc=contoso,dc=test",
        group_base_dn: "ou=groups,dc=contoso,dc=test",
        user_filter: "(objectClass=user)",
        group_filter: "(objectClass=group)",
        attribute_mapping: mapping,
        absence_policy: LdapAbsencePolicy::Delete,
        max_group_depth: 7,
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
    assert_eq!(read.port, 389);
    assert_eq!(read.tls_mode, LdapTlsMode::StartTls);
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
    assert_eq!(read.absence_policy, LdapAbsencePolicy::Delete);
    assert_eq!(read.max_group_depth, 7);
    assert!(read.active, "a new connector is active");
}

#[tokio::test]
async fn a_connector_cannot_be_pointed_at_another_scopes_organization() {
    // A connector aimed at a neighbouring environment's organization would sync that
    // organization's users, so this must be refused. It is worth being precise about WHAT
    // refuses it, because the first version of this comment credited the wrong mechanism:
    //
    // `OrganizationId` is scope-typed, and `create` compares the handle's scope to its own
    // before any SQL runs. So this test is stopped by that guard and never reaches the
    // statement. Deleting the SQL `EXISTS` entirely leaves this test passing.
    //
    // That does not make the `EXISTS` redundant, and the two things it does are covered
    // elsewhere: refusing an organization that does not exist at all (the next test, where
    // dropping the clause falls through to a raw foreign-key violation rather than
    // `NotFound`), and refusing a SOFT-DELETED one, which the foreign key still matches and
    // the scope guard cannot see -- see
    // `a_connector_aimed_at_a_deleted_organization_is_refused`, the only test that fails when
    // the `AND deleted_at IS NULL` conjunct is removed.
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

/// Every variant of both closed sets survives a write and a read.
///
/// The shared fixture deliberately carries the NON-default variants, which is what lets the
/// round-trip test see a write path that drops the caller's choice. This covers the other side,
/// so the default-valued variants are not left untested by that move.
#[tokio::test]
async fn every_transport_and_absence_variant_round_trips() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Contoso").await;
    let mapping = serde_json::json!({});

    for (tls, absence, depth) in [
        (LdapTlsMode::Ldaps, LdapAbsencePolicy::Deactivate, 0),
        (LdapTlsMode::StartTls, LdapAbsencePolicy::Delete, 64),
        (LdapTlsMode::Plaintext, LdapAbsencePolicy::Deactivate, 1),
    ] {
        let id = LdapConnectorId::generate(&env, &scope);
        let mut new = spec(&id, &org, &mapping);
        new.tls_mode = tls;
        new.absence_policy = absence;
        new.max_group_depth = depth;
        db.control_store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .ldap_connectors()
            .create(&env, new)
            .await
            .expect("create");

        let read = db
            .control_store()
            .scoped(scope)
            .ldap_connectors()
            .get(&id)
            .await
            .expect("read back");
        assert_eq!(read.tls_mode, tls, "tls_mode did not survive the write");
        assert_eq!(
            read.absence_policy, absence,
            "absence_policy did not survive"
        );
        assert_eq!(
            read.max_group_depth, depth,
            "max_group_depth did not survive"
        );
    }
}

/// A connector cannot be aimed at an organization that has been deleted.
///
/// This is the ONLY thing the `EXISTS` in the insert does that nothing else already does. The
/// foreign key still matches a soft-deleted organization, because the row is retained, and the
/// typed scope guard only covers the cross-scope case. Removing the `AND deleted_at IS NULL`
/// conjunct left the whole suite green before this existed.
#[tokio::test]
async fn a_connector_aimed_at_a_deleted_organization_is_refused() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Contoso").await;

    db.control_store()
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .organizations(scope)
        .delete(&env, &org)
        .await
        .expect("soft-delete the organization");

    let id = LdapConnectorId::generate(&env, &scope);
    let mapping = serde_json::json!({});
    let outcome = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .ldap_connectors()
        .create(&env, spec(&id, &org, &mapping))
        .await;

    assert!(
        matches!(outcome, Err(StoreError::NotFound)),
        "a connector aimed at a deleted organization must be refused: {outcome:?}"
    );
}

/// The twin of the `tls_mode` skew test, for the arm that had none.
///
/// The doc on `ldap_connector_from_row` claims BOTH closed sets decode as an error rather than a
/// default. Only `tls_mode` was measured: replacing the `absence_policy` arm with
/// `unwrap_or(Deactivate)` -- and, worse, with `unwrap_or(Delete)` -- left the suite green.
/// `Delete` is the dangerous direction: a policy this build cannot read would become the one
/// that removes accounts.
#[tokio::test]
async fn an_absence_policy_this_build_does_not_know_is_an_error_and_not_a_default() {
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
        "ALTER TABLE ldap_connectors DROP CONSTRAINT ldap_connectors_absence_policy_known, \
         ADD CONSTRAINT ldap_connectors_absence_policy_known \
             CHECK (absence_policy IN ('deactivate', 'delete', 'quarantine'))",
    )
    .execute(db.owner_pool())
    .await
    .expect("widen the constraint the way a later migration would");
    sqlx::query("UPDATE ldap_connectors SET absence_policy = 'quarantine' WHERE id = $1")
        .bind(id.to_string())
        .execute(db.owner_pool())
        .await
        .expect("write the policy this build has never heard of");

    let error = db
        .control_store()
        .scoped(scope)
        .ldap_connectors()
        .get(&id)
        .await
        .expect_err("an unknown absence_policy must not decode to anything");
    assert!(
        matches!(error, StoreError::Database(_)),
        "it must surface as a decode failure rather than a silent default: {error:?}"
    );
}

/// The isolation is the POLICY, not the repository's `WHERE` clause.
///
/// Every statement in `LdapConnectorRepo` carries an explicit scope predicate, so the row-level
/// policy is pure defence in depth and no test asked the database directly. Replacing the policy
/// body with `USING (true) WITH CHECK (true)` passed all six tests, all 47 migration tests and
/// `scoped-table-registration.sh`, which reads the FORCE-RLS set and never a policy predicate.
#[tokio::test]
async fn the_isolation_policy_and_not_only_the_where_clause_refuses_a_neighbour() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let one = db.seed_scope(&env).await;
    let two = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, one, "Contoso").await;
    let id = LdapConnectorId::generate(&env, &one);
    let mapping = serde_json::json!({});
    db.control_store()
        .scoped(one)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .ldap_connectors()
        .create(&env, spec(&id, &org, &mapping))
        .await
        .expect("write in scope one");

    let mut conn = db.control_pool().acquire().await.expect("acquire");
    sqlx::query("SELECT set_config('ironauth.tenant_id', $1, false)")
        .bind(two.tenant().to_string())
        .execute(&mut *conn)
        .await
        .expect("pin tenant to scope two");
    sqlx::query("SELECT set_config('ironauth.environment_id', $1, false)")
        .bind(two.environment().to_string())
        .execute(&mut *conn)
        .await
        .expect("pin environment to scope two");

    // No WHERE clause at all: whatever comes back is what the POLICY allowed.
    let rows = sqlx::query("SELECT id FROM ldap_connectors")
        .fetch_all(&mut *conn)
        .await
        .expect("raw read");
    assert!(
        rows.is_empty(),
        "a raw read pinned to another scope saw a connector, so the policy is not the boundary"
    );
}

/// The control plane's UPDATE privilege covers exactly the columns a statement writes.
///
/// 0212 first granted UPDATE table-wide while its only UPDATE (`set_active`) writes two columns.
/// The withheld ones are not incidental: `organization_id` decides whose directory is read,
/// `tls_mode` whether the bind is encrypted, and `bind_secret_name` which credential is used.
/// A privilege for a write nothing performs is one nobody can account for later.
///
/// Derived from the catalog rather than from the migration text, so editing the GRANT without
/// editing this test is what fails.
#[tokio::test]
async fn the_control_update_grant_is_scoped_to_the_columns_a_statement_writes() {
    let db = TestDatabase::start().await;
    let granted: Vec<String> = sqlx::query_scalar(
        "SELECT column_name::text FROM information_schema.column_privileges \
         WHERE table_name = 'ldap_connectors' AND grantee = 'ironauth_control' \
           AND privilege_type = 'UPDATE' ORDER BY column_name",
    )
    .fetch_all(db.owner_pool())
    .await
    .expect("read the catalog");

    assert_eq!(
        granted,
        vec!["active".to_owned(), "updated_at".to_owned()],
        "the control plane's UPDATE grant is not the set `set_active` writes"
    );
    for withheld in ["organization_id", "tls_mode", "bind_secret_name", "host"] {
        assert!(
            !granted.iter().any(|c| c == withheld),
            "{withheld} is updatable by the control plane and no statement writes it"
        );
    }
}
