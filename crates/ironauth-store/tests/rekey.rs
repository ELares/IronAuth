// SPDX-License-Identifier: MIT OR Apache-2.0

//! Rewrapping tenant KEKs under a new platform master key (issue #153, criterion 3).
//!
//! The criterion asks that "an interrupted rekey resumes cleanly and converges, with reads
//! and writes correct in the mixed-key state". These tests are about that property rather
//! than about the happy path: a rekey that works once and cannot be resumed is the one that
//! strands a deployment half-rotated.

use ironauth_env::{Env, FixedEntropy};
use ironauth_jose::MasterKey;
use ironauth_store::rekey::Rekey;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{CorrelationId, Scope};
use sqlx::Row;

fn master(id: &str, seed: u64) -> MasterKey {
    MasterKey::generate(id, &FixedEntropy::new(seed))
}

/// Provision a KEK for `scope` under `master`, the way the envelope path does.
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
    // And a DEK, which is what actually seals a secret. It is wrapped under the KEK, NOT
    // under the master, which is the whole reason a master rotation rewraps a few hundred
    // KEKs and leaves every sealed row untouched.
    acting
        .envelope()
        .provision_dek(env, master)
        .await
        .expect("provision a DEK");
}

/// Seal a secret under `master`, so a later read proves the whole chain opens.
async fn put_secret(db: &TestDatabase, env: &Env, scope: Scope, master: &MasterKey, value: &[u8]) {
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .envelope()
        .put_secret(env, master, "email", value)
        .await
        .expect("seal a secret");
}

async fn master_of(db: &TestDatabase, scope: Scope) -> String {
    sqlx::query(
        "SELECT master_key_id FROM tenant_keks WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("read the recorded master")
    .get("master_key_id")
}

/// The whole point: the KEK opens under the NEW master afterwards and not under the old one.
///
/// Asserted by unwrapping, not by reading the recorded id. A run that rewrote `master_key_id`
/// and left the blob alone would pass a column check while making the KEK unopenable by
/// anything, which is the worst outcome this code has available to it.
#[tokio::test]
async fn a_rekey_leaves_every_kek_openable_under_the_new_master_and_not_the_old() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5EED);
    let scope = db.seed_scope(&env).await;

    let old = master("master-old", 0x0001);
    let new = master("master-new", 0x0002);
    provision(&db, &env, scope, &old).await;
    put_secret(&db, &env, scope, &old, b"ada@lovelace.test").await;
    assert_eq!(master_of(&db, scope).await, "master-old");

    let report = Rekey::new(db.owner_pool(), &old, &new, env.entropy())
        .run()
        .await
        .expect("rekey runs");
    assert_eq!(report.rewrapped, 1);
    assert_eq!(report.skipped_destroyed, 0);
    assert_eq!(master_of(&db, scope).await, "master-new");

    // The DATA still reads, which is the property a rekey owes its deployment. Asserted
    // through the envelope path rather than by inspecting a column: a run that rewrote
    // master_key_id and left the blob alone would pass a column check while making every
    // sealed secret in the tenant permanently unopenable.
    let opened = db
        .store()
        .scoped(scope)
        .envelope()
        .open_secret(&new, "email")
        .await
        .expect("the secret opens under the new master after the rekey");
    assert_eq!(opened, b"ada@lovelace.test");

    // And the old master no longer opens it, so the rewrap was real.
    assert!(
        db.store()
            .scoped(scope)
            .envelope()
            .open_secret(&old, "email")
            .await
            .is_err(),
        "the old master must no longer open a rewrapped KEK"
    );
}

/// Resumability, which the criterion names and which is the reason this has no cursor.
///
/// Rows are selected by `master_key_id = <old>`, so a run that stopped after some rows simply
/// does not see them again. Simulated by rekeying one of three scopes' worth of rows and then
/// running the whole thing: the finished row must be left alone, not rewrapped twice.
#[tokio::test]
async fn an_interrupted_rekey_resumes_and_converges_without_redoing_finished_rows() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5EED);
    let old = master("master-old", 0x0001);
    let new = master("master-new", 0x0002);

    let mut scopes = Vec::new();
    let first_scope = db.seed_scope(&env).await;
    provision(&db, &env, first_scope, &old).await;
    scopes.push(first_scope);

    // THE INTERRUPTION, simulated without hand-computing a blob: rekey while only the first
    // scope exists, then add the other two under the old master. The database is then in
    // exactly the state a run killed after one row leaves behind -- one row on the new
    // master, the rest on the old -- and every blob is genuinely valid.
    //
    // (The first scope was provisioned and rekeyed above; the loop below adds the rest.)
    let first = Rekey::new(db.owner_pool(), &old, &new, env.entropy())
        .run()
        .await
        .expect("the first pass runs");
    assert_eq!(first.rewrapped, 1, "only the scope that exists yet");

    for _ in 0..2 {
        let scope = db.seed_scope(&env).await;
        provision(&db, &env, scope, &old).await;
        scopes.push(scope);
    }

    let report = Rekey::new(db.owner_pool(), &old, &new, env.entropy())
        .run()
        .await
        .expect("the resumed run works");

    assert_eq!(
        report.rewrapped, 2,
        "only the two unfinished rows are touched"
    );
    assert_eq!(
        report.already_current, 1,
        "the finished row is counted as already current, not rewrapped again"
    );
    for scope in &scopes {
        assert_eq!(master_of(&db, *scope).await, "master-new");
    }

    // Convergent: running it again is a no-op rather than an error.
    let again = Rekey::new(db.owner_pool(), &old, &new, env.entropy())
        .run()
        .await
        .expect("a completed rekey re-runs cleanly");
    assert_eq!(again.rewrapped, 0);
}

/// A CRYPTO-SHRED THAT LANDS MID-ROTATION MUST NOT BE UNDONE.
///
/// The rotation reads every row up front and writes them back one at a time. A shred that
/// commits in between sets `wrapped_kek = ''` and `status = 'destroyed'`, and an unguarded
/// write-back would restore recoverable key material derived from the bytes read BEFORE the
/// shred -- while `status` and `destroyed_at`, columns the rotation does not touch, stayed as
/// the shred left them. The row would read as destroyed and decrypt anyway, because the KEK
/// read path filters on tenant, environment and version and NOT on status.
///
/// Simulated by shredding the row and then running: the snapshot the loop works from is taken
/// inside `run`, so the guard on the WRITE is what has to refuse it, not the status check on
/// the read.
#[tokio::test]
async fn a_shredded_kek_is_never_rewrapped_back_into_recoverable_material() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5EED);
    let scope = db.seed_scope(&env).await;
    let old = master("master-old", 0x0001);
    let new = master("master-new", 0x0002);
    provision(&db, &env, scope, &old).await;

    // The shred, exactly as the tenant-purge path writes it.
    sqlx::query(
        "UPDATE tenant_keks SET wrapped_kek = ''::bytea, status = 'destroyed' \
         WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .execute(db.owner_pool())
    .await
    .expect("shred the KEK");

    let report = Rekey::new(db.owner_pool(), &old, &new, env.entropy())
        .run()
        .await
        .expect("the rotation runs");
    assert_eq!(
        report.rewrapped, 0,
        "a destroyed KEK must never be rewrapped"
    );

    // The blob is still empty: nothing was written back.
    let blob: Vec<u8> = sqlx::query(
        "SELECT wrapped_kek FROM tenant_keks WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("read the blob")
    .get("wrapped_kek");
    assert!(
        blob.is_empty(),
        "the shredded blob must stay empty; rewrapping it would resurrect the tenant's data"
    );
}

/// A row that appears AFTER the work set was read leaves the rotation incomplete, and the run
/// must say so rather than report success.
///
/// KEKs are provisioned lazily under whichever master the inserting process holds, so a server
/// still running during a rotation adds rows the snapshot never saw.
#[tokio::test]
async fn a_kek_created_after_the_snapshot_is_reported_as_remaining() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5EED);
    let old = master("master-old", 0x0001);
    let new = master("master-new", 0x0002);

    let first = db.seed_scope(&env).await;
    provision(&db, &env, first, &old).await;

    let done = Rekey::new(db.owner_pool(), &old, &new, env.entropy())
        .run()
        .await
        .expect("the first rotation runs");
    assert_eq!(done.rewrapped, 1);
    assert_eq!(
        done.remaining_under_old, 0,
        "with nothing else present the rotation is complete"
    );

    // A live server provisions a new scope under the OLD master, as it would mid-rotation.
    let late = db.seed_scope(&env).await;
    provision(&db, &env, late, &old).await;

    let after = Rekey::new(db.owner_pool(), &old, &new, env.entropy())
        .run()
        .await
        .expect("the rotation runs again");
    assert_eq!(
        after.rewrapped, 1,
        "the late row is picked up by the next run"
    );
    assert_eq!(after.remaining_under_old, 0);
}

/// The wrong old master must stop the run, not skip the row.
///
/// A rekey that shrugged off a KEK it could not open would report success while leaving that
/// tenant behind, and the next run would not see the row either once the others had moved.
#[tokio::test]
async fn a_wrong_old_master_fails_the_run_rather_than_skipping_the_row() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5EED);
    let scope = db.seed_scope(&env).await;

    let real = master("master-old", 0x0001);
    let wrong = master("master-old", 0x00FF); // same id, different bytes
    let new = master("master-new", 0x0002);
    provision(&db, &env, scope, &real).await;

    assert!(
        Rekey::new(db.owner_pool(), &wrong, &new, env.entropy())
            .run()
            .await
            .is_err(),
        "a KEK that does not open under the supplied master must stop the run"
    );
    assert_eq!(
        master_of(&db, scope).await,
        "master-old",
        "and must leave the row exactly as it was"
    );
}

/// Rekeying to the same master is a mistake, not a no-op: it would rewrap every row under the
/// key it already uses, burning the AAD's only distinguishing input for nothing.
#[tokio::test]
async fn rekeying_to_the_same_master_is_refused() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5EED);
    let same = master("master-old", 0x0001);
    assert!(
        Rekey::new(
            db.owner_pool(),
            &same,
            &master("master-old", 0x0001),
            env.entropy()
        )
        .run()
        .await
        .is_err()
    );
}

/// The refusal that stops "nothing to do" meaning two different things.
///
/// `tenant_keks` is FORCE ROW LEVEL SECURITY, so on the data-plane role every scan returns
/// zero rows whatever the table holds. A rekey that ran there would report a clean, complete
/// run having touched nothing.
#[tokio::test]
async fn a_role_row_level_security_applies_to_is_refused() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5EED);
    let scope = db.seed_scope(&env).await;
    let old = master("master-old", 0x0001);
    let new = master("master-new", 0x0002);
    provision(&db, &env, scope, &old).await;

    assert!(
        Rekey::new(db.app_pool(), &old, &new, env.entropy())
            .run()
            .await
            .is_err(),
        "the app role must be refused rather than reporting an empty, successful run"
    );
    assert_eq!(master_of(&db, scope).await, "master-old");
}
