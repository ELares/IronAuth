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
    seed_connector_in(db, env, scope).await.1
}

/// The same, returning the organization the connector belongs to as well.
async fn seed_connector_in(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
) -> (OrganizationId, LdapConnectorId) {
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
                bind_secret_name: "ldap_bind_contoso",
                user_base_dn: "ou=people,dc=contoso,dc=test",
                group_base_dn: "",
                user_filter: "(objectClass=user)",
                group_filter: "",
                attribute_mapping: &mapping,
                absence_policy: LdapAbsencePolicy::Deactivate,
                max_group_depth: 5,
            },
            None,
        )
        .await
        .expect("create connector");
    (org, id)
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

    assert_eq!(all.opened.get(&first.to_string()), Some(&ids(&["u-1"])));
    assert_eq!(
        all.opened.get(&second.to_string()),
        Some(&ids(&["u-2", "u-3"]))
    );
    assert!(
        !all.opened.contains_key(&never.to_string()),
        "a connector with no snapshot must not appear with an empty set"
    );
    assert_eq!(all.opened.len(), 2, "{all:?}");
    assert!(all.unreadable.is_empty(), "{all:?}");
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
            .opened
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
    let (org, connector) = seed_connector_in(&db, &env, scope).await;
    record(&db, &env, scope, &connector, &ids(&["u-a"])).await;

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .ldap_connectors()
        .delete(&env, &org, &connector)
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

/// A DEK ROTATION MUST NOT ORPHAN AN EXISTING SNAPSHOT. The row records the generation it was
/// sealed under, and the reader resolves that generation rather than the active one -- so a
/// rotation between two passes leaves the previous population readable and absence still
/// detectable. Reading under the ACTIVE key instead would make every rotation look like a
/// directory nobody had ever swept.
#[tokio::test]
async fn a_snapshot_survives_a_dek_rotation() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let connector = seed_connector(&db, &env, scope).await;
    record(&db, &env, scope, &connector, &ids(&["u-a", "u-b"])).await;

    let before: i32 =
        sqlx::query("SELECT dek_version FROM ldap_sync_snapshots WHERE connector_id = $1")
            .bind(connector.to_string())
            .fetch_one(db.owner_pool())
            .await
            .expect("read")
            .get("dek_version");

    // AS THE OWNER: rotation writes `tenant_deks`, which neither low-privilege role may touch.
    // In production that is a key-management action, not something a sweep does.
    ironauth_store::Store::from_pool(db.owner_pool().clone())
        .with_master_key(db.master_key())
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .envelope()
        .rotate_dek(&env, &db.master_key())
        .await
        .expect("rotate the DEK");

    let after = db
        .control_store()
        .scoped(scope)
        .envelope()
        .active_dek_version()
        .await
        .expect("read the active version");
    assert_eq!(
        after,
        Some(before + 1),
        "the rotation did not advance the generation, so this test proves nothing"
    );

    assert_eq!(
        db.control_store()
            .scoped(scope)
            .ldap_sync_snapshots()
            .get(&connector)
            .await
            .expect("the old generation still opens"),
        Some(ids(&["u-a", "u-b"])),
        "a rotation orphaned the previous pass's snapshot"
    );
    let all = db
        .control_store()
        .scoped(scope)
        .ldap_sync_snapshots()
        .all_in_scope()
        .await
        .expect("read them all");
    assert!(
        all.unreadable.is_empty(),
        "the rotated-past snapshot reads as unreadable: {all:?}"
    );
    assert_eq!(
        all.opened.get(&connector.to_string()),
        Some(&ids(&["u-a", "u-b"]))
    );
}

/// THE LABEL IS THE ONLY THING SEPARATING A SNAPSHOT FROM A SECRET. Both seals bind the label,
/// the scope, one free text and the DEK version -- so if the two labels were ever equal, a
/// secret whose NAME matched a connector id and a snapshot for that connector would become
/// interchangeable ciphertexts. `bind_secret_name` is operator-chosen, so that collision is
/// reachable by configuration rather than by attack.
#[tokio::test]
async fn a_secret_ciphertext_and_a_snapshot_ciphertext_are_not_interchangeable() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let connector = seed_connector(&db, &env, scope).await;
    // THE COLLIDING NAME: a secret named exactly the connector id, which an operator may choose.
    let name = connector.to_string();

    record(&db, &env, scope, &connector, &ids(&["u-a"])).await;
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .environment_secrets()
        .put(&env, &db.master_key(), &name, b"the-bind-password", None)
        .await
        .expect("store a secret under the connector's own id");

    let snapshot_blob: Vec<u8> =
        sqlx::query("SELECT ciphertext FROM ldap_sync_snapshots WHERE connector_id = $1")
            .bind(connector.to_string())
            .fetch_one(db.owner_pool())
            .await
            .expect("read")
            .get("ciphertext");
    let secret_blob: Vec<u8> =
        sqlx::query("SELECT ciphertext FROM environment_secrets WHERE name = $1")
            .bind(&name)
            .fetch_one(db.owner_pool())
            .await
            .expect("read")
            .get("ciphertext");

    // Swap them.
    sqlx::query("UPDATE ldap_sync_snapshots SET ciphertext = $1 WHERE connector_id = $2")
        .bind(&secret_blob)
        .bind(connector.to_string())
        .execute(db.owner_pool())
        .await
        .expect("swap into the snapshot");
    sqlx::query("UPDATE environment_secrets SET ciphertext = $1 WHERE name = $2")
        .bind(&snapshot_blob)
        .bind(&name)
        .execute(db.owner_pool())
        .await
        .expect("swap into the secret");

    assert!(
        db.control_store()
            .scoped(scope)
            .ldap_sync_snapshots()
            .get(&connector)
            .await
            .is_err(),
        "a secret's ciphertext authenticated as this connector's snapshot"
    );
    assert!(
        db.store()
            .scoped(scope)
            .environment_secrets()
            .open_value(&db.master_key(), &name)
            .await
            .is_err(),
        "a snapshot's ciphertext authenticated as this secret's value, so a bind password can be \
         replaced by a directory population"
    );
}

/// THE RECORDED INSTANT IS THE ONE THE CALLER GAVE, read from the raw column rather than through
/// the reader that inverts the writer. Asserting the reader against the writer only proves the
/// two agree with each other: changing `microseconds` to `milliseconds` in the writer AND
/// `* 1000000` to `* 1000` in the reader leaves that assertion green while the column is off by
/// a factor of a thousand.
#[tokio::test]
async fn the_stored_instant_is_the_one_the_caller_gave() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let connector = seed_connector(&db, &env, scope).await;
    // A FIXED INSTANT, not the clock: 2026-01-02T03:04:05.678901Z.
    let taken: i64 = 1_767_323_045_678_901;

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .ldap_sync_snapshots()
        .record(&env, &db.master_key(), &connector, &ids(&["u-a"]), taken)
        .await
        .expect("record");

    let rendered: String = sqlx::query(
        "SELECT to_char(taken_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US') AS t \
                     FROM ldap_sync_snapshots WHERE connector_id = $1",
    )
    .bind(connector.to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("read the raw column")
    .get("t");
    assert_eq!(
        rendered, "2026-01-02T03:04:05.678901",
        "the column does not hold the instant the caller gave"
    );

    let meta = db
        .control_store()
        .scoped(scope)
        .ldap_sync_snapshots()
        .meta_in_scope()
        .await
        .expect("read metadata");
    assert_eq!(
        meta.get(&connector.to_string())
            .expect("present")
            .taken_at_unix_micros,
        taken,
        "the reader disagrees with the column"
    );
}
