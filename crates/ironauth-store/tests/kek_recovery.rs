// SPDX-License-Identifier: MIT OR Apache-2.0

//! Recovering a wrapped KEK hierarchy from a backup (issue #153, criterion 6).
//!
//! The criterion asks that the KEK backup and restore runbook be published and "its restore
//! path is exercised by a test that recovers a KMS-wrapped hierarchy". `docs/KEK-RECOVERY.md`
//! is the runbook; this file is the exercise, and the two are meant to be read together: the
//! runbook's steps are the ones these tests perform, in the same order.
//!
//! # What is being recovered, and what is not
//!
//! The hierarchy is master key, then per-tenant KEK wrapped under it, then per-record DEK
//! wrapped under the KEK. A backup of the KEK rows is therefore NOT a backup of anything
//! readable: every blob in it is sealed under a master key held outside the database. That is
//! the property that makes the backup safe to store beside the data, and it is also the
//! property that makes the master key the single thing whose loss is unrecoverable.
//!
//! These tests recover from the loss of the DATABASE ROWS. They cannot recover from the loss
//! of the master key, and one of them proves that rather than leaving it implied.

use ironauth_env::{Env, FixedEntropy};
use ironauth_jose::MasterKey;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{CorrelationId, Scope};
use sqlx::Row;

fn master(id: &str, seed: u64) -> MasterKey {
    MasterKey::generate(id, &FixedEntropy::new(seed))
}

/// One backed-up KEK row: the wrapped material and everything needed to put it back.
///
/// Deliberately the whole row rather than just the blob. The AAD binds the scope, the
/// version and the master key id into the wrap, so a restore that put the blob back under a
/// different version would produce a row that exists and cannot be opened.
#[derive(Debug, Clone)]
struct BackedUpKek {
    id: String,
    tenant_id: String,
    environment_id: String,
    version: i32,
    master_key_id: String,
    wrapped_kek: Vec<u8>,
    status: String,
}

/// STEP 1 of the runbook: export the wrapped hierarchy.
async fn back_up_keks(db: &TestDatabase) -> Vec<BackedUpKek> {
    sqlx::query(
        "SELECT id, tenant_id, environment_id, version, master_key_id, wrapped_kek, status \
         FROM tenant_keks ORDER BY id",
    )
    .fetch_all(db.owner_pool())
    .await
    .expect("export the KEK rows")
    .into_iter()
    .map(|row| BackedUpKek {
        id: row.get("id"),
        tenant_id: row.get("tenant_id"),
        environment_id: row.get("environment_id"),
        version: row.get("version"),
        master_key_id: row.get("master_key_id"),
        wrapped_kek: row.get("wrapped_kek"),
        status: row.get("status"),
    })
    .collect()
}

/// STEP 3 of the runbook: put the exported rows back.
async fn restore_keks(db: &TestDatabase, backup: &[BackedUpKek]) {
    for kek in backup {
        sqlx::query(
            "INSERT INTO tenant_keks \
               (id, tenant_id, environment_id, version, master_key_id, wrapped_kek, status) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&kek.id)
        .bind(&kek.tenant_id)
        .bind(&kek.environment_id)
        .bind(kek.version)
        .bind(&kek.master_key_id)
        .bind(&kek.wrapped_kek)
        .bind(&kek.status)
        .execute(db.owner_pool())
        .await
        .expect("restore a KEK row");
    }
}

/// STEP 2, simulated: the KEK rows are gone. The sealed data is untouched, which is the
/// realistic shape of the failure -- a dropped table, a bad migration, a restore of the wrong
/// snapshot -- rather than total loss of the database.
async fn lose_keks(db: &TestDatabase) {
    sqlx::query("DELETE FROM tenant_keks")
        .execute(db.owner_pool())
        .await
        .expect("lose the KEK rows");
}

async fn provision(db: &TestDatabase, env: &Env, scope: Scope, master: &MasterKey) {
    let acting = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env));
    acting
        .envelope()
        .provision_kek(env, master)
        .await
        .expect("provision a KEK");
    acting
        .envelope()
        .provision_dek(env, master)
        .await
        .expect("provision a DEK");
}

async fn put_secret(db: &TestDatabase, env: &Env, scope: Scope, master: &MasterKey, value: &[u8]) {
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .envelope()
        .put_secret(env, master, "email", value)
        .await
        .expect("seal a secret");
}

async fn open_secret(
    db: &TestDatabase,
    scope: Scope,
    master: &MasterKey,
) -> Result<Vec<u8>, ironauth_store::StoreError> {
    db.store()
        .scoped(scope)
        .envelope()
        .open_secret(master, "email")
        .await
}

/// THE RUNBOOK'S RESTORE PATH, end to end.
///
/// Back up the wrapped hierarchy, lose the rows, restore them, and read a secret sealed
/// before the loss. The read is the assertion that matters: a restore that puts rows back and
/// leaves them unopenable has produced a database that looks recovered and is not.
#[tokio::test]
async fn a_lost_kek_hierarchy_is_recovered_from_a_backup_and_secrets_open_again() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5EED);
    let master = master("master-1", 0x0001);

    let mut scopes = Vec::new();
    for index in 0..3 {
        let scope = db.seed_scope(&env).await;
        provision(&db, &env, scope, &master).await;
        put_secret(
            &db,
            &env,
            scope,
            &master,
            format!("secret-{index}").as_bytes(),
        )
        .await;
        scopes.push(scope);
    }

    let backup = back_up_keks(&db).await;
    assert_eq!(backup.len(), 3, "one KEK per scope");
    assert!(
        backup.iter().all(|kek| !kek.wrapped_kek.is_empty()),
        "a backup of empty blobs would restore nothing and pass a row count check"
    );

    lose_keks(&db).await;
    assert!(
        open_secret(&db, scopes[0], &master).await.is_err(),
        "precondition: with the KEK gone the secret cannot be opened"
    );

    restore_keks(&db, &backup).await;

    for (index, scope) in scopes.iter().enumerate() {
        assert_eq!(
            open_secret(&db, *scope, &master)
                .await
                .expect("the restored hierarchy opens"),
            format!("secret-{index}").into_bytes(),
            "scope {index}: the secret sealed before the loss must read back"
        );
    }
}

/// A RESTORE UNDER THE WRONG MASTER FAILS LOUDLY.
///
/// The wrap AAD binds the master key id, so a KEK wrapped under one master cannot be
/// unwrapped under another. This asserts the failure is an ERROR rather than plaintext that
/// happens to be wrong, which is the difference between a restore that stops and one that
/// quietly serves garbage as a user's email address.
#[tokio::test]
async fn a_restore_under_the_wrong_master_key_refuses_rather_than_returning_garbage() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5EED);
    let right = master("master-right", 0x0001);
    let wrong = master("master-wrong", 0x0002);

    let scope = db.seed_scope(&env).await;
    provision(&db, &env, scope, &right).await;
    put_secret(&db, &env, scope, &right, b"the-secret").await;

    let backup = back_up_keks(&db).await;
    lose_keks(&db).await;
    restore_keks(&db, &backup).await;

    // The rows are back and correct. The master is the thing that is wrong.
    assert!(
        open_secret(&db, scope, &wrong).await.is_err(),
        "a wrong master must refuse, not decrypt to something"
    );
    assert_eq!(
        open_secret(&db, scope, &right)
            .await
            .expect("the right master still opens it"),
        b"the-secret"
    );
}

/// THE MASTER KEY IS THE THING WHOSE LOSS IS UNRECOVERABLE, and the runbook says so.
///
/// Stated as a test rather than a sentence because it is the one fact an operator most needs
/// to believe BEFORE an incident: no quantity of database backups substitutes for the master
/// key, since every blob in them is sealed under it.
#[tokio::test]
async fn a_backup_of_the_hierarchy_is_useless_without_the_master_key() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5EED);
    let master_key = master("master-1", 0x0001);

    let scope = db.seed_scope(&env).await;
    provision(&db, &env, scope, &master_key).await;
    put_secret(&db, &env, scope, &master_key, b"the-secret").await;

    let backup = back_up_keks(&db).await;

    // Every byte of the backup is sealed: the plaintext appears nowhere in it.
    for kek in &backup {
        assert!(
            !kek.wrapped_kek
                .windows(b"the-secret".len())
                .any(|window| window == b"the-secret"),
            "a backup must not carry recoverable material"
        );
    }

    // And with a different master, a complete and correct backup opens nothing.
    lose_keks(&db).await;
    restore_keks(&db, &backup).await;
    let lost_master = master("master-1", 0xDEAD);
    assert!(
        open_secret(&db, scope, &lost_master).await.is_err(),
        "the same master key ID with different material must not open the hierarchy"
    );
}

/// A SHREDDED KEK STAYS SHREDDED ACROSS A RESTORE.
///
/// Crypto-shred is how a tenant's data is made unrecoverable on request. A backup taken
/// before the shred would undo it, so the runbook has to say which backups must be aged out
/// and this test pins the half the code controls: restoring the row AS IT STANDS after a
/// shred does not resurrect anything.
#[tokio::test]
async fn restoring_a_shredded_kek_does_not_resurrect_it() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5EED);
    let master_key = master("master-1", 0x0001);

    let scope = db.seed_scope(&env).await;
    provision(&db, &env, scope, &master_key).await;
    put_secret(&db, &env, scope, &master_key, b"the-secret").await;

    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .envelope()
        .destroy_kek(&env)
        .await
        .expect("shred the KEK");

    let after_shred = back_up_keks(&db).await;
    assert!(
        after_shred.iter().all(|kek| kek.wrapped_kek.is_empty()),
        "a shred empties the wrapped material, which is what makes it a shred"
    );

    lose_keks(&db).await;
    restore_keks(&db, &after_shred).await;
    assert!(
        open_secret(&db, scope, &master_key).await.is_err(),
        "restoring a post-shred backup must not make the data readable again"
    );
}
