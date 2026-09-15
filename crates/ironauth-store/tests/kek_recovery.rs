// SPDX-License-Identifier: MIT OR Apache-2.0

//! Recovering a wrapped KEK hierarchy from a backup (issue #153, criterion 6).
//!
//! The criterion asks that the KEK backup and restore runbook be published and "its restore
//! path is exercised by a test that recovers a KMS-wrapped hierarchy". `docs/KEK-RECOVERY.md`
//! is the runbook; this file is the exercise. The runbook's steps and these tests drive the
//! SAME two functions, `kek_backup::export` and `kek_backup::restore`, which is the only
//! relationship between the two artifacts that is actually enforced.
//!
//! An earlier version of the runbook claimed "a change to one that is not made to the other
//! fails the suite". Nothing computed any relationship between them, no gate read the
//! document, and the two had already drifted on which step number does what. The claim is
//! gone. What replaced it is weaker and true: the document tells an operator to run two
//! commands, those commands call these functions, and these tests call them too, so a change
//! to what the functions DO reaches both. A change to the prose still reaches neither.
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
use ironauth_store::kek_backup::{BackedUpKek, RestoreReport, manifest_for};
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{CorrelationId, Scope};

fn master(id: &str, seed: u64) -> MasterKey {
    MasterKey::generate(id, &FixedEntropy::new(seed))
}

/// THE RUNBOOK'S BACKUP STEP, through the code the runbook names.
///
/// This file used to declare its OWN private `BackedUpKek` and its own insert loop, so the
/// `kek_backup` module that criterion 4 exists for had no caller anywhere and
/// `dormant-module-scan.sh` was red. A review found it and the point was sharper than the
/// gate: verification that nothing on the documented path calls is verification that never
/// runs. These helpers now drive `export` and `restore`, the same two functions
/// `ironauth storage kek-backup` and `ironauth storage kek-restore` call.
async fn back_up_keks(db: &TestDatabase) -> Vec<BackedUpKek> {
    ironauth_store::kek_backup::export(db.owner_pool())
        .await
        .expect("export the KEK rows")
}

/// The runbook's restore step: verify against the manifest, then write in one transaction.
async fn restore_keks(db: &TestDatabase, backup: &[BackedUpKek]) -> RestoreReport {
    let manifest = manifest_for(backup);
    ironauth_store::kek_backup::restore(db.owner_pool(), backup, &manifest)
        .await
        .expect("restore the KEK rows")
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

    let _ = restore_keks(&db, &backup).await;

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
    let _ = restore_keks(&db, &backup).await;

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

    // WHICH DIMENSION THIS ACTUALLY MEASURES, stated because it is less than it looks.
    //
    // `right` and `wrong` differ in BOTH id and key material, so all the assertions above
    // show is that different material fails to decrypt. A review varied only the id, same
    // seed so `MasterKey::generate` yields identical material, and got `Ok("the-secret")`.
    //
    // That is correct behaviour and it is worth pinning rather than hiding: the unwrap AAD is
    // built from the `master_key_id` recorded ON THE ROW, never from the key the caller
    // holds, which is what lets rows on two master generations coexist during a rekey. The
    // consequence for an operator is the part the runbook must not overstate: matching the
    // key id is NOT what makes a restore work, the material is, and nothing compares the
    // running key's id against the rows.
    let same_material_different_id = master("master-renamed", 0x0001);
    assert_eq!(
        open_secret(&db, scope, &same_material_different_id)
            .await
            .expect("the AAD comes from the row, so matching material opens it"),
        b"the-secret",
        "a key with the right material and a different id opens the hierarchy: the id in \
         the row is what the AAD binds, and no check compares it against the running key"
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
    let _ = restore_keks(&db, &backup).await;
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
    let _ = restore_keks(&db, &after_shred).await;
    assert!(
        open_secret(&db, scope, &master_key).await.is_err(),
        "restoring a post-shred backup must not make the data readable again"
    );
}

/// A BACKUP TAKEN ON A ROLE ROW-LEVEL SECURITY APPLIES TO IS REFUSED, NOT SILENTLY EMPTY.
///
/// The runbook used to hand the operator a bare `SELECT ... FROM tenant_keks`. A review ran it
/// as the three roles a deployment has and measured `owner=Ok(3) app=Ok(0) control=Ok(0)`:
/// zero rows and NO ERROR on the role a `database.url` actually names. An empty export then
/// passes everything downstream, because it matches its own count and digests to its own
/// manifest, and the backup is discovered worthless during the key loss it was taken for.
///
/// Both halves are asserted, because the danger is the CONTRAST: the owner sees the rows and
/// the app role must not quietly see none.
#[tokio::test]
async fn a_backup_from_a_row_level_security_role_is_refused_rather_than_returning_no_rows() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5EED);
    let the_master = master("master-1", 0x0001);
    let scope = db.seed_scope(&env).await;
    provision(&db, &env, scope, &the_master).await;

    assert!(
        !back_up_keks(&db).await.is_empty(),
        "precondition: the unrestricted role exports the rows"
    );

    // The SAME export, on the role a deployment's `database.url` names.
    let refused = ironauth_store::kek_backup::export(db.app_pool()).await;
    assert!(
        refused.is_err(),
        "the export must REFUSE a connection row-level security applies to. Returning the \
         zero rows it can see is the failure this guards: an empty backup verifies against \
         its own manifest and recovers nothing"
    );
}

/// A RESTORE THAT CANNOT FINISH WRITES NOTHING AT ALL.
///
/// The documented restore used to be a per-row INSERT loop with no transaction. A review ran
/// it against a database holding one retained row, got a duplicate-key error partway, and was
/// left with two rows of three: neither the old state nor the new one, and an error naming a
/// constraint rather than which tenants got in. `tenant_keks` has no DELETE grant, so
/// retained rows are the ordinary case rather than a contrived one.
#[tokio::test]
async fn a_restore_that_conflicts_writes_nothing() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5EED);
    let the_master = master("master-1", 0x0001);

    let mut scopes = Vec::new();
    for _ in 0..3 {
        let scope = db.seed_scope(&env).await;
        provision(&db, &env, scope, &the_master).await;
        put_secret(&db, &env, scope, &the_master, b"the-secret").await;
        scopes.push(scope);
    }
    let backup = back_up_keks(&db).await;
    assert_eq!(backup.len(), 3, "precondition");

    // Lose the rows, then let ONE come back DIFFERENT: the shape of a database that moved on.
    lose_keks(&db).await;
    let mut moved_on = backup[1].clone();
    moved_on.master_key_id = "master-2".to_owned();
    let manifest = manifest_for(std::slice::from_ref(&moved_on));
    ironauth_store::kek_backup::restore(
        db.owner_pool(),
        std::slice::from_ref(&moved_on),
        &manifest,
    )
    .await
    .expect("the single differing row lands");

    let manifest = manifest_for(&backup);
    let result = ironauth_store::kek_backup::restore(db.owner_pool(), &backup, &manifest).await;
    assert!(
        matches!(
            result,
            Err(ironauth_store::kek_backup::RestoreError::Conflict { .. })
        ),
        "a row present with DIFFERENT contents stops the restore: overwriting it could undo \
         a crypto-shred or discard a rotation, got {result:?}"
    );

    assert_eq!(
        count_keks(&db).await,
        1,
        "and NOTHING was written: one transaction, so the database is exactly as it was, \
         rather than the half-written state an operator cannot reason about"
    );
}

/// RE-RUNNING AN INTERRUPTED RESTORE CONVERGES INSTEAD OF DYING ON ITS OWN FIRST HALF.
///
/// The old loop's re-run "inserted 0 of 3" because every row it had already written collided.
#[tokio::test]
async fn a_restore_rerun_over_its_own_rows_converges() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5EED);
    let the_master = master("master-1", 0x0001);
    for _ in 0..3 {
        let scope = db.seed_scope(&env).await;
        provision(&db, &env, scope, &the_master).await;
    }
    let backup = back_up_keks(&db).await;
    lose_keks(&db).await;

    let first = restore_keks(&db, &backup).await;
    assert_eq!(first.restored, 3);
    assert_eq!(first.already_present, 0);

    let second = restore_keks(&db, &backup).await;
    assert_eq!(second.restored, 0, "the second run writes nothing new");
    assert_eq!(
        second.already_present, 3,
        "and reports the rows it found identical rather than failing on them"
    );
    assert_eq!(count_keks(&db).await, 3, "no duplicates");
}

/// THE TWO TIMESTAMP COLUMNS SURVIVE THE ROUND TRIP.
///
/// The export carried seven of nine columns. `created_at` has a `now()` DEFAULT so it was
/// reset to the restore instant on every row, and `destroyed_at`, the crypto-shred instant the
/// migration calls "retained as evidence", came back NULL. A review measured both: a shredded
/// row still said the key was destroyed and no longer said when.
#[tokio::test]
async fn a_restore_preserves_the_creation_and_shred_instants() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5EED);
    let the_master = master("master-1", 0x0001);
    let scope = db.seed_scope(&env).await;
    provision(&db, &env, scope, &the_master).await;
    put_secret(&db, &env, scope, &the_master, b"the-secret").await;

    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .envelope()
        .destroy_kek(&env)
        .await
        .expect("crypto-shred the scope");

    let backup = back_up_keks(&db).await;
    let shredded = backup
        .iter()
        .find(|kek| kek.status == "destroyed")
        .expect("the shredded row is in the backup");
    assert!(
        shredded.destroyed_at.is_some(),
        "precondition: the shred stamped the erasure instant, so there is something to lose"
    );
    let created_before = shredded.created_at.clone();
    let destroyed_before = shredded.destroyed_at.clone();

    lose_keks(&db).await;
    let _ = restore_keks(&db, &backup).await;

    let after = back_up_keks(&db).await;
    let restored = after
        .iter()
        .find(|kek| kek.id == shredded.id)
        .expect("the row came back");
    assert_eq!(
        restored.destroyed_at, destroyed_before,
        "the erasure record must survive: a restored shredded row that says the key was \
         destroyed and not WHEN has no answer for an erasure attestation"
    );
    assert_eq!(
        restored.created_at, created_before,
        "and the creation instant must not be reset to the incident date by the column \
         DEFAULT"
    );
}

/// How many KEK rows the database holds.
async fn count_keks(db: &TestDatabase) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM tenant_keks")
        .fetch_one(db.owner_pool())
        .await
        .expect("count the KEK rows")
}
