// SPDX-License-Identifier: MIT OR Apache-2.0

//! What the last completed pass saw in a directory (issue #142).
//!
//! # What this owes
//!
//! The snapshot is the only thing that makes absence detectable, so its failure modes are the
//! deprovisioning failure modes:
//!
//! - it is SEALED, because a stable identifier can be a DN and a DN carries a person's name and
//!   their place in an organization. A plaintext column would be an index of everybody in the
//!   customer's directory;
//! - the seal is bound to its CONNECTOR, so one directory's population cannot be lifted onto
//!   another connector in the same environment -- which would make that directory's whole
//!   population read as departed on the next pass;
//! - "no snapshot" and "a snapshot of nobody" are DIFFERENT. The first means nothing has ever
//!   read this directory and nobody may be concluded to have left it; the second means a pass
//!   read it and it was empty.

#![cfg(feature = "testing")]

use std::collections::BTreeSet;

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, LdapAbsencePolicy, LdapConnectorId, LdapTlsMode, NewLdapConnector,
    OrganizationId, Scope,
};
use sqlx::Row;

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

async fn seed_org(db: &TestDatabase, env: &Env, scope: Scope) -> OrganizationId {
    let id = OrganizationId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .organizations(scope)
        .create(env, &id, now(env), "Directory Co", None)
        .await
        .expect("create organization");
    id
}

/// A connector row, because a snapshot's foreign key demands one.
async fn seed_connector(db: &TestDatabase, env: &Env, scope: Scope) -> LdapConnectorId {
    let org = seed_org(db, env, scope).await;
    let id = LdapConnectorId::generate(env, &scope);
    let mapping = serde_json::json!({ "userName": "uid" });
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
                user_base_dn: "ou=people,dc=contoso,dc=test",
                group_base_dn: "",
                user_filter: "(objectClass=user)",
                group_filter: "",
                attribute_mapping: &mapping,
                absence_policy: LdapAbsencePolicy::Deactivate,
                max_group_depth: 5,
            },
        )
        .await
        .expect("create connector");
    id
}

fn ids(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

async fn record(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    id: &LdapConnectorId,
    set: &BTreeSet<String>,
) {
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .ldap_sync_snapshots()
        .record(env, &db.master_key(), id, set, now(env))
        .await
        .expect("record the snapshot");
}

/// THE ROUND TRIP, and the replacement. A pass replaces what the pass before it recorded; a
/// snapshot that appended would make everybody who ever appeared permanently present, and nobody
/// would ever be detected as absent.
#[tokio::test]
async fn a_snapshot_round_trips_and_the_next_pass_replaces_it() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let connector = seed_connector(&db, &env, scope).await;

    record(&db, &env, scope, &connector, &ids(&["u-a", "u-b", "u-c"])).await;
    assert_eq!(
        db.control_store()
            .scoped(scope)
            .ldap_sync_snapshots()
            .get(&connector)
            .await
            .expect("read"),
        Some(ids(&["u-a", "u-b", "u-c"]))
    );

    record(&db, &env, scope, &connector, &ids(&["u-a"])).await;
    assert_eq!(
        db.control_store()
            .scoped(scope)
            .ldap_sync_snapshots()
            .get(&connector)
            .await
            .expect("read"),
        Some(ids(&["u-a"])),
        "the second pass appended to the first instead of replacing it"
    );
}

/// NO SNAPSHOT IS NOT AN EMPTY SNAPSHOT. The difference decides whether anybody is deprovisioned:
/// a directory nothing has ever read offers no evidence that anybody left it, while a directory
/// that was read and held nobody is a real (and refused) observation.
#[tokio::test]
async fn a_connector_that_never_swept_is_distinguishable_from_one_that_saw_nobody() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let never = seed_connector(&db, &env, scope).await;
    let empty = seed_connector(&db, &env, scope).await;

    record(&db, &env, scope, &empty, &BTreeSet::new()).await;

    let repo = db.control_store();
    let repo = repo.scoped(scope);
    assert_eq!(
        repo.ldap_sync_snapshots().get(&never).await.expect("read"),
        None,
        "a connector nothing has swept must have no snapshot at all"
    );
    assert_eq!(
        repo.ldap_sync_snapshots().get(&empty).await.expect("read"),
        Some(BTreeSet::new()),
        "a pass that saw nobody recorded something, and it is not nothing"
    );
}

/// THE IDENTIFIERS ARE NOT IN THE ROW. A DN carries a person's name; the column must not.
#[tokio::test]
async fn the_stored_row_holds_no_plaintext_identifier() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let connector = seed_connector(&db, &env, scope).await;

    record(
        &db,
        &env,
        scope,
        &connector,
        &ids(&["uid=ada.lovelace,ou=People,dc=contoso,dc=test"]),
    )
    .await;

    let ciphertext: Vec<u8> =
        sqlx::query("SELECT ciphertext FROM ldap_sync_snapshots WHERE connector_id = $1")
            .bind(connector.to_string())
            .fetch_one(db.owner_pool())
            .await
            .expect("read the row")
            .get("ciphertext");
    let as_text = String::from_utf8_lossy(&ciphertext);
    assert!(
        !as_text.contains("ada.lovelace"),
        "the directory identifier is readable in the stored bytes"
    );
    assert!(
        !as_text.contains("ou=People"),
        "the directory structure is readable in the stored bytes"
    );
}

/// THE SEAL IS BOUND TO ITS CONNECTOR. Lifting one directory's snapshot onto another connector in
/// the same environment would make that directory's whole population read as departed on the next
/// pass, which under a delete policy is unrecoverable.
#[tokio::test]
async fn a_snapshot_lifted_onto_another_connector_will_not_open() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let source = seed_connector(&db, &env, scope).await;
    let victim = seed_connector(&db, &env, scope).await;

    record(&db, &env, scope, &source, &ids(&["u-a", "u-b"])).await;
    record(&db, &env, scope, &victim, &ids(&["u-x"])).await;

    // The lift: the source's ciphertext under the victim's connector id.
    let stolen: Vec<u8> =
        sqlx::query("SELECT ciphertext FROM ldap_sync_snapshots WHERE connector_id = $1")
            .bind(source.to_string())
            .fetch_one(db.owner_pool())
            .await
            .expect("read")
            .get("ciphertext");
    sqlx::query("UPDATE ldap_sync_snapshots SET ciphertext = $1 WHERE connector_id = $2")
        .bind(&stolen)
        .bind(victim.to_string())
        .execute(db.owner_pool())
        .await
        .expect("lift the ciphertext");

    let opened = db
        .control_store()
        .scoped(scope)
        .ldap_sync_snapshots()
        .get(&victim)
        .await;
    assert!(
        opened.is_err(),
        "another connector's snapshot opened as this one's: {opened:?}"
    );
    assert_eq!(
        db.control_store()
            .scoped(scope)
            .ldap_sync_snapshots()
            .get(&source)
            .await
            .expect("the source still opens"),
        Some(ids(&["u-a", "u-b"])),
        "the lift must not have disturbed the source"
    );
}

/// ONE QUERY FOR THE WHOLE SCOPE, which is what a pass reads before it opens any connection. A
/// connector with no snapshot is ABSENT rather than present-and-empty, for the reason above.
#[tokio::test]
async fn every_snapshot_in_the_scope_comes_back_keyed_by_connector() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let first = seed_connector(&db, &env, scope).await;
    let second = seed_connector(&db, &env, scope).await;
    let never = seed_connector(&db, &env, scope).await;

    record(&db, &env, scope, &first, &ids(&["u-1"])).await;
    record(&db, &env, scope, &second, &ids(&["u-2", "u-3"])).await;

    let all = db
        .control_store()
        .scoped(scope)
        .ldap_sync_snapshots()
        .all_in_scope()
        .await
        .expect("read them all");

    assert_eq!(all.get(&first.to_string()), Some(&ids(&["u-1"])));
    assert_eq!(all.get(&second.to_string()), Some(&ids(&["u-2", "u-3"])));
    assert!(
        !all.contains_key(&never.to_string()),
        "a connector with no snapshot must not appear with an empty set"
    );
    assert_eq!(all.len(), 2, "{all:?}");
}

/// ANOTHER ENVIRONMENT'S SNAPSHOTS ARE INVISIBLE. The same isolation every table here has, on the
/// one table that holds a list of people.
#[tokio::test]
async fn a_snapshot_is_invisible_from_another_scope() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let mine = db.seed_scope(&env).await;
    let theirs = db.seed_scope(&env).await;
    let connector = seed_connector(&db, &env, mine).await;
    record(&db, &env, mine, &connector, &ids(&["u-secret"])).await;

    assert!(
        db.control_store()
            .scoped(theirs)
            .ldap_sync_snapshots()
            .all_in_scope()
            .await
            .expect("read")
            .is_empty(),
        "another environment can see this directory's population"
    );
    assert_eq!(
        db.control_store()
            .scoped(theirs)
            .ldap_sync_snapshots()
            .get(&connector)
            .await
            .expect("read"),
        None,
        "a connector id from another scope resolved a snapshot"
    );
}

/// THE METADATA SURFACE RETURNS NO IDENTIFIERS. An operator watching a directory shrink should
/// see the count without any path that returns the population.
#[tokio::test]
async fn the_metadata_reports_size_and_age_without_contents() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let connector = seed_connector(&db, &env, scope).await;
    let taken = now(&env);

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .ldap_sync_snapshots()
        .record(
            &env,
            &db.master_key(),
            &connector,
            &ids(&["u-a", "u-b", "u-c"]),
            taken,
        )
        .await
        .expect("record");

    let meta = db
        .control_store()
        .scoped(scope)
        .ldap_sync_snapshots()
        .meta_in_scope()
        .await
        .expect("read metadata");
    let one = meta.get(&connector.to_string()).expect("present");
    assert_eq!(one.principal_count, 3, "the count is not the set's size");
    assert_eq!(
        one.taken_at_unix_micros, taken,
        "the recorded instant is not the one the caller gave"
    );
}

/// THE SNAPSHOT DIES WITH ITS CONNECTOR. A set of identifiers whose directory has been removed is
/// PII nothing will ever read again.
#[tokio::test]
async fn removing_the_connector_removes_its_snapshot() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let connector = seed_connector(&db, &env, scope).await;
    record(&db, &env, scope, &connector, &ids(&["u-a"])).await;

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .ldap_connectors()
        .delete(&env, &connector)
        .await
        .expect("delete the connector");

    let left: i64 =
        sqlx::query("SELECT count(*) AS c FROM ldap_sync_snapshots WHERE connector_id = $1")
            .bind(connector.to_string())
            .fetch_one(db.owner_pool())
            .await
            .expect("count")
            .get("c");
    assert_eq!(left, 0, "the snapshot outlived its directory");
}
