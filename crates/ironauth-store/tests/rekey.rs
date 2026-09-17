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
/// WHICH GUARD THIS TEST ACTUALLY REACHES. The shred commits BEFORE `run()` is called, so the
/// snapshot taken inside `run` already reads `status = 'destroyed'` and the `continue` in the
/// loop refuses the row; `store_rewrapped_kek` is never called. This said the opposite ("the
/// guard on the WRITE is what has to refuse it, not the status check on the read"), and a
/// review traced the execution and found the write guard unreached. The sentence mattered
/// because a later doc block built an argument on top of it.
///
/// The write guard is covered by `a_shred_landing_after_the_snapshot_is_refused_by_the_write`
/// below, which commits the shred AFTER the snapshot is taken, which is the ordering the write
/// guard exists for.
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

/// THE ORDERING THE WRITE GUARD ACTUALLY EXISTS FOR: a shred that lands AFTER the snapshot.
///
/// The test above commits its shred before `run` is called, so the loop's own status check
/// refuses the row and `store_rewrapped_kek` is never reached. That leaves the guard on the
/// write, which the code documents as "what actually protects the erasure", with nothing
/// behind it. A review traced the execution and found it unreached while its test's doc
/// claimed the opposite.
///
/// Producing the ordering needs a seam, because the snapshot is taken INSIDE `run`:
/// `with_after_snapshot` (testing only) runs the shred between the read and the first write.
/// The loop's status check sees `'active'` from the snapshot and lets the row through; only
/// the compare-and-swap can refuse it now.
#[tokio::test]
async fn a_shred_landing_after_the_snapshot_is_refused_by_the_write() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5EED);
    let scope = db.seed_scope(&env).await;
    let old = master("master-old", 0x0001);
    let new = master("master-new", 0x0002);
    provision(&db, &env, scope, &old).await;

    let pool = db.owner_pool().clone();
    let tenant = scope.tenant().to_string();
    let environment = scope.environment().to_string();
    let report = Rekey::new(db.owner_pool(), &old, &new, env.entropy())
        .with_after_snapshot(move || {
            let pool = pool.clone();
            let tenant = tenant.clone();
            let environment = environment.clone();
            Box::pin(async move {
                sqlx::query(
                    "UPDATE tenant_keks SET wrapped_kek = ''::bytea, status = 'destroyed' \
                     WHERE tenant_id = $1 AND environment_id = $2",
                )
                .bind(tenant)
                .bind(environment)
                .execute(&pool)
                .await
                .expect("shred the KEK between the snapshot and the write");
            })
        })
        .run()
        .await
        .expect("the rotation runs");

    assert_eq!(
        report.rewrapped, 0,
        "the write must refuse a row the snapshot read as active and the shred has since \
         destroyed"
    );
    assert_eq!(
        report.contended, 1,
        "and report it as contention, which is the signal the operator is told to examine"
    );

    let (blob, status): (Vec<u8>, String) = sqlx::query(
        "SELECT wrapped_kek, status FROM tenant_keks \
         WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .map(|row| (row.get("wrapped_kek"), row.get("status")))
    .expect("read the row back");
    assert!(
        blob.is_empty(),
        "the erasure stands: restoring the blob under the new master while status and \
         destroyed_at stayed as the shred left them is the silent un-erasure this guards"
    );
    assert_eq!(status, "destroyed", "and the row still reads as destroyed");
}

/// THE STATUS TERM OF THE COMPARE-AND-SWAP, ON ITS OWN.
///
/// The shred test above does not measure it. A shred writes `wrapped_kek = ''` as well as
/// `status = 'destroyed'`, so `wrapped_kek = $2` refuses the row by itself and the whole
/// `AND status = $4` term can be deleted with every test in this file green. A review made
/// exactly that point about the term this PR originally shipped, and the first version of the
/// test above reproduced it.
///
/// So vary ONLY the status: retire the row between the snapshot and the write, leaving the
/// blob byte-identical. Now nothing except `status = $4` can refuse it.
///
/// Refusing is the correct answer and it is convergent, not a stall: the row is counted as
/// contention, the closing check sees it is not on the target, and the next pass reads it as
/// retired and rewraps it under the status it now has.
#[tokio::test]
async fn a_status_change_after_the_snapshot_is_refused_by_the_write() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5EED);
    let scope = db.seed_scope(&env).await;
    let old = master("master-old", 0x0001);
    let new = master("master-new", 0x0002);
    provision(&db, &env, scope, &old).await;

    let blob_before = wrapped_kek_of(&db, scope).await;
    let pool = db.owner_pool().clone();
    let tenant = scope.tenant().to_string();
    let environment = scope.environment().to_string();
    let report = Rekey::new(db.owner_pool(), &old, &new, env.entropy())
        .with_after_snapshot(move || {
            let pool = pool.clone();
            let tenant = tenant.clone();
            let environment = environment.clone();
            Box::pin(async move {
                // THE BLOB IS NOT TOUCHED. That is the whole point: `wrapped_kek = $2` still
                // matches, so only the status term can refuse this write.
                sqlx::query(
                    "UPDATE tenant_keks SET status = 'retired' \
                     WHERE tenant_id = $1 AND environment_id = $2",
                )
                .bind(tenant)
                .bind(environment)
                .execute(&pool)
                .await
                .expect("retire the KEK between the snapshot and the write");
            })
        })
        .run()
        .await
        .expect("the rotation runs");

    assert_eq!(
        blob_before,
        wrapped_kek_of(&db, scope).await,
        "precondition: the hook changed the status and NOTHING else, so this test measures \
         the status term rather than the blob term beside it"
    );
    assert_eq!(
        report.rewrapped, 0,
        "a row whose status changed since the snapshot is not still as it was read"
    );
    assert_eq!(report.contended, 1, "and it is reported as contention");

    // CONVERGENT, not stalled: the next pass reads the row as retired and moves it.
    let next = Rekey::new(db.owner_pool(), &old, &new, env.entropy())
        .run()
        .await
        .expect("the next pass runs");
    assert_eq!(
        next.rewrapped, 1,
        "the next pass picks it up with its new status"
    );
    assert_eq!(next.remaining_off_target, 0, "and the rotation converges");
}

/// The wrapped blob recorded for `scope`, so a fixture can prove it changed nothing else.
async fn wrapped_kek_of(db: &TestDatabase, scope: Scope) -> Vec<u8> {
    sqlx::query("SELECT wrapped_kek FROM tenant_keks WHERE tenant_id = $1 AND environment_id = $2")
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .fetch_one(db.owner_pool())
        .await
        .expect("read the blob")
        .get("wrapped_kek")
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
        done.remaining_off_target, 0,
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
    assert_eq!(after.remaining_off_target, 0);
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

/// Open a sealed secret, so a read proves the KEK-to-DEK-to-ciphertext chain still works.
async fn open_secret(db: &TestDatabase, scope: Scope, master: &MasterKey) -> Vec<u8> {
    open_secret_result(db, scope, master)
        .await
        .expect("open the sealed secret")
}

/// [`open_secret`] without the unwrap, for the assertions that need the REFUSAL.
async fn open_secret_result(
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

/// Every KEK status recorded for `scope`, so a fixture can prove it built the state it claims.
async fn kek_statuses(db: &TestDatabase, scope: Scope) -> Vec<String> {
    sqlx::query(
        "SELECT status FROM tenant_keks \
         WHERE tenant_id = $1 AND environment_id = $2 ORDER BY version",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_all(db.owner_pool())
    .await
    .expect("read the recorded statuses")
    .iter()
    .map(|row| row.get::<String, _>("status"))
    .collect()
}

/// THE OTHER HALF OF CRITERION 3: "reads and writes correct IN THE MIXED-KEY STATE".
///
/// `an_interrupted_rekey_resumes_and_converges_without_redoing_finished_rows` covers the
/// resume and the convergence, and it asserts counts and recorded master ids. It never reads
/// or writes a secret while the rotation is half-done, so the half of the criterion about
/// data being usable mid-rotation had nothing behind it.
///
/// That is the half an operator actually feels. A rotation that converges perfectly while
/// the deployment cannot read a tenant's secrets is an outage, and it is an outage that
/// looks like a successful migration in every report the rotation produces.
///
/// The mixed state here is real rather than simulated: one scope is on the new master and
/// two are still on the old, which is exactly what a run killed after one row leaves behind.
#[tokio::test]
async fn reads_and_writes_are_correct_while_the_rotation_is_half_done() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5EED);
    let old = master("master-old", 0x0001);
    let new = master("master-new", 0x0002);

    // Scope A exists first and gets rotated; B and C arrive afterwards on the old master.
    let rotated = db.seed_scope(&env).await;
    provision(&db, &env, rotated, &old).await;
    put_secret(&db, &env, rotated, &old, b"rotated-before").await;

    let first = Rekey::new(db.owner_pool(), &old, &new, env.entropy())
        .run()
        .await
        .expect("the first pass runs");
    assert_eq!(
        first.rewrapped, 1,
        "precondition: exactly one scope is rotated"
    );

    let mut pending = Vec::new();
    for _ in 0..2 {
        let scope = db.seed_scope(&env).await;
        provision(&db, &env, scope, &old).await;
        put_secret(&db, &env, scope, &old, b"pending-before").await;
        pending.push(scope);
    }

    // The database is now genuinely mixed.
    assert_eq!(master_of(&db, rotated).await, "master-new");
    for scope in &pending {
        assert_eq!(master_of(&db, *scope).await, "master-old");
    }

    // READ, both sides of the rotation, each under the master its KEK is wrapped with.
    assert_eq!(
        open_secret(&db, rotated, &new).await,
        b"rotated-before",
        "a secret sealed BEFORE the rotation must still open on a rotated scope"
    );
    for scope in &pending {
        assert_eq!(
            open_secret(&db, *scope, &old).await,
            b"pending-before",
            "and an unrotated scope must still open under the old master"
        );
    }

    // WRITE, on both sides, while the rotation is still half-done.
    put_secret(&db, &env, rotated, &new, b"rotated-during").await;
    for scope in &pending {
        put_secret(&db, &env, *scope, &old, b"pending-during").await;
    }
    assert_eq!(open_secret(&db, rotated, &new).await, b"rotated-during");
    for scope in &pending {
        assert_eq!(open_secret(&db, *scope, &old).await, b"pending-during");
    }

    // AND THE OTHER DIRECTION, which is the half that says what the mixed window COSTS.
    //
    // Everything above hands each scope the master its own row records, so nothing above
    // depends on the mixture it just built. This comment used to read "the property that
    // makes the mid-rotation window safe to serve traffic in", and a review showed that is
    // false and that the test could not have caught it: a running IronAuth process builds
    // exactly ONE master key (`resolve_master_key` in the binary derives "master-1" and the
    // config exposes a single `master_key`), so a fleet held up during the window has one of
    // these two keys and NOT the other. The module doc and the CLI banner both say so, in
    // those words: OFFLINE operation, stop the fleet.
    //
    // So the honest property is the opposite one, and it is asserted rather than described: a
    // process holding ONE master cannot open the other side. That is why the rotation is
    // offline, and it is the assertion that would go red if someone made the window look
    // serveable without first landing the master key RING the module doc names as the
    // prerequisite.
    assert!(
        open_secret_result(&db, rotated, &old).await.is_err(),
        "a process holding only the OLD master cannot read a rotated scope"
    );
    for scope in &pending {
        assert!(
            open_secret_result(&db, *scope, &new).await.is_err(),
            "and a process holding only the NEW master cannot read a scope still pending"
        );
    }

    // Finish the rotation.
    let report = Rekey::new(db.owner_pool(), &old, &new, env.entropy())
        .run()
        .await
        .expect("the resumed pass runs");
    assert_eq!(
        report.rewrapped, 2,
        "only the two that were still on the old master"
    );
    assert_eq!(report.already_current, 1);
    assert_eq!(report.remaining_off_target, 0, "the rotation converged");

    // ONLY THE PENDING SCOPES MEASURE THE CLAIM. The rotated scope was asserted 20 lines
    // above and the converging pass selects `master_key_id = old`, so it provably never
    // touched that row: re-reading it here carried the message "a write made during the
    // mixed state is readable after convergence" over an assertion that could not fail
    // unless the earlier one already had.
    for scope in &pending {
        assert_eq!(
            open_secret(&db, *scope, &new).await,
            b"pending-during",
            "a write made during the mixed state, on a scope rotated AFTER that write, is \
             readable under the new master once the rotation converges"
        );
    }
}

/// THE UNWRAP CONTEXT COMES FROM THE ROW, NOT FROM THE KEY THE CALLER HOLDS.
///
/// This is the one production line that lets two rows on two different master generations
/// coexist, and until this test nothing pinned it: `fetch_active_kek` and `fetch_kek_by_version`
/// build the unwrap AAD from the `master_key_id` recorded ON THE ROW. Replacing that with the
/// caller's own `master.id()` left all fourteen rekey and envelope tests green, because every
/// other test hands a scope the master its row already names, so the two expressions are equal
/// everywhere they are evaluated.
///
/// Separating them needs two master keys with the SAME key material and DIFFERENT ids, which
/// `MasterKey::derive` allows: it derives the key from the ikm alone and carries the id beside
/// it. The material opens the blob either way, so the ONLY thing that can refuse the read is
/// the AAD, and the AAD is the thing under test.
#[tokio::test]
async fn the_unwrap_context_is_the_rows_master_generation_not_the_callers() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5EED);
    let scope = db.seed_scope(&env).await;

    // Same material, two ids. `derive` keys off the ikm only.
    let material = [0x42_u8; 32];
    let recorded = MasterKey::derive("master-recorded", &material);
    let twin = MasterKey::derive("master-twin", &material);
    assert_ne!(
        recorded.id(),
        twin.id(),
        "precondition: the two keys differ in the only way that matters here"
    );

    provision(&db, &env, scope, &recorded).await;
    put_secret(&db, &env, scope, &recorded, b"under-recorded").await;
    assert_eq!(master_of(&db, scope).await, "master-recorded");

    // The twin's MATERIAL unwraps the blob. If the AAD were built from the caller's id this
    // would fail, because the wrap bound "master-recorded" and the caller names "master-twin".
    assert_eq!(
        open_secret(&db, scope, &twin).await,
        b"under-recorded",
        "the read binds the master generation the ROW records, so a key with the right \
         material opens it whatever id that key carries; deriving the context from the \
         caller's own id instead is the change that breaks every mixed-generation read the \
         day a master key ring lands"
    );
}

/// A RETIRED KEK VERSION MUST NOT STRAND THE ROTATION.
///
/// `rotate_kek` leaves the superseded version beside the new one with `status = 'retired'`.
/// The rewrap loop skips only `'destroyed'`, so a retired row is read and rewrapped in memory,
/// and the write used to bind `status = 'active'` and refuse it. The row was counted as
/// contention, the closing count counted it as work left undone, and the CLI exited FAILURE
/// telling the operator to stop the fleet and run it again, on this run and on every rerun.
/// The old master could never be decommissioned, which is the point of the rotation.
///
/// Three consecutive passes, because "forever" is the part that matters: a defect that clears
/// on the second run is an inconvenience, one that does not is a deployment that cannot finish.
#[tokio::test]
async fn a_retired_kek_version_is_rewrapped_rather_than_stranding_the_rotation() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5EED);
    let scope = db.seed_scope(&env).await;
    let old = master("master-old", 1);
    let new = master("master-new", 2);

    provision(&db, &env, scope, &old).await;
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .envelope()
        .rotate_kek(&env, &old)
        .await
        .expect("rotate the KEK, leaving the previous version retired");

    let statuses = kek_statuses(&db, scope).await;
    assert!(
        statuses.iter().any(|status| status == "retired"),
        "precondition: the rotation really left a retired version behind, got {statuses:?}"
    );

    for pass in 1..=3 {
        let report = Rekey::new(db.owner_pool(), &old, &new, env.entropy())
            .run()
            .await
            .expect("the pass runs");
        assert_eq!(
            report.contended, 0,
            "pass {pass}: a retired row is ordinary work, not contention"
        );
        assert_eq!(
            report.remaining_off_target, 0,
            "pass {pass}: the rotation converged, so the old master can be destroyed"
        );
    }
}

/// A ROW ON A THIRD MASTER MUST NOT READ AS CONVERGED.
///
/// The closing check counted rows still under the SOURCE master, which answers "is anything
/// left behind?" and never "is everything where it should be?". Those differ as soon as a
/// rotation is retargeted: `old -> mid` stops part way, then `old -> new` runs, and the rows
/// already on `mid` are outside the work set (it selects `master_key_id = old`) AND outside a
/// count keyed on `old`. The run reported converged, the operator destroyed `old`, and those
/// tenants were unreadable with no key left that could open them.
#[tokio::test]
async fn a_kek_parked_on_a_third_master_is_not_reported_as_converged() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5EED);
    let old = master("master-old", 1);
    let mid = master("master-mid", 2);
    let new = master("master-new", 3);

    let stranded = db.seed_scope(&env).await;
    provision(&db, &env, stranded, &old).await;
    put_secret(&db, &env, stranded, &old, b"stranded").await;

    // The abandoned retarget: this scope moves to `mid` and the operator then aims elsewhere.
    Rekey::new(db.owner_pool(), &old, &mid, env.entropy())
        .run()
        .await
        .expect("the abandoned pass runs");
    assert_eq!(master_of(&db, stranded).await, "master-mid");

    let ordinary = db.seed_scope(&env).await;
    provision(&db, &env, ordinary, &old).await;

    let report = Rekey::new(db.owner_pool(), &old, &new, env.entropy())
        .run()
        .await
        .expect("the retargeted pass runs");
    assert_eq!(report.rewrapped, 1, "it moves the row it can see");
    assert!(
        report.remaining_off_target > 0,
        "and it must NOT report convergence while a live KEK sits on a master that is \
         neither the source nor the target: reporting success here is what lets an operator \
         destroy the only key that could still open it"
    );
    assert_eq!(
        open_secret(&db, stranded, &mid).await,
        b"stranded",
        "the stranded row is still readable, but only by a key this rotation never named"
    );
}

/// A SERVER HOLDING A RING SERVES A ROTATION IN PROGRESS (issue #153 criterion 2).
///
/// This is the property the whole criterion rests on and nothing covered. `rekey.rs` says the
/// operation is offline because "a server holds ONE master key, so between the first rewrapped
/// row and the last, a live process cannot open both shapes", and names a master key ring on the
/// read path as what it needs first.
///
/// The mixed state here is real rather than simulated: one scope is rewrapped and one is not,
/// exactly as a resumed or interrupted rekey leaves the database. One key value opens both.
#[tokio::test]
async fn a_ring_opens_both_shapes_while_a_rotation_is_half_done() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5EED);
    let old = master("master-old", 0x0001);
    let new = master("master-new", 0x0002);

    let rotated = db.seed_scope(&env).await;
    provision(&db, &env, rotated, &old).await;
    put_secret(&db, &env, rotated, &old, b"rotated").await;

    // THE PASS RUNS BEFORE THE SECOND SCOPE EXISTS, which is how this suite builds a genuinely
    // mixed database rather than editing rows: the rekey moves what is there, and the scope that
    // arrives afterwards is written under the old master, exactly as one arriving mid-rotation
    // would be.
    let report = Rekey::new(db.owner_pool(), &old, &new, env.entropy())
        .run()
        .await
        .expect("the pass runs");
    assert_eq!(report.rewrapped, 1, "precondition: exactly one scope moved");

    let untouched = db.seed_scope(&env).await;
    provision(&db, &env, untouched, &old).await;
    put_secret(&db, &env, untouched, &old, b"not-yet").await;

    // NEITHER KEY ALONE CAN SERVE THIS, which is why the ring exists. Established first, so the
    // ring's success below is a contrast rather than an assertion in isolation.
    let new_only = master("master-new", 0x0002);
    let old_only = master("master-old", 0x0001);
    let new_fails = open_secret_result(&db, untouched, &new_only).await.is_err()
        || open_secret_result(&db, rotated, &new_only).await.is_err();
    let old_fails = open_secret_result(&db, untouched, &old_only).await.is_err()
        || open_secret_result(&db, rotated, &old_only).await.is_err();
    assert!(
        new_fails && old_fails,
        "a single master must fail on one side or the other, or this database is not mixed and \
         the ring below would be proving nothing"
    );

    // THE RING: the incoming master, carrying the outgoing one as a predecessor.
    let ring = master("master-new", 0x0002).with_previous(master("master-old", 0x0001));
    assert_eq!(
        open_secret(&db, rotated, &ring).await,
        b"rotated",
        "the rewrapped scope opens under the new master"
    );
    assert_eq!(
        open_secret(&db, untouched, &ring).await,
        b"not-yet",
        "and the scope the pass has not reached opens under the predecessor"
    );
}

/// A PREDECESSOR CANNOT BECOME THE KEY NEW DATA IS WRITTEN UNDER.
///
/// The ring widens what can be READ. If it also widened what is written, a rotation would never
/// converge: rows would keep being produced under the key being retired, and the rekey's
/// completion count would never reach zero.
#[tokio::test]
async fn a_ring_wraps_new_work_under_the_current_master_only() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5EED);
    let ring = master("master-new", 0x0002).with_previous(master("master-old", 0x0001));

    let scope = db.seed_scope(&env).await;
    provision(&db, &env, scope, &ring).await;
    put_secret(&db, &env, scope, &ring, b"fresh").await;

    assert_eq!(
        master_of(&db, scope).await,
        "master-new",
        "a KEK provisioned through a ring records the CURRENT master, never a predecessor"
    );
    // And the predecessor alone cannot open it, which is the same statement from the other side.
    assert!(
        open_secret_result(&db, scope, &master("master-old", 0x0001))
            .await
            .is_err()
    );
}

/// A MASTER THE RING DOES NOT HOLD FAILS CLOSED rather than opening anything.
#[tokio::test]
async fn a_ring_without_the_wrapping_master_refuses() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5EED);
    let old = master("master-old", 0x0001);

    let scope = db.seed_scope(&env).await;
    provision(&db, &env, scope, &old).await;
    put_secret(&db, &env, scope, &old, b"sealed").await;

    // A ring carrying a DIFFERENT predecessor: the right shape, the wrong generation.
    let ring = master("master-new", 0x0002).with_previous(master("master-other", 0x0003));
    assert!(open_secret_result(&db, scope, &ring).await.is_err());
}

/// WHAT A ROTATION DOES NOT CARRY: the blind indexes (issue #153).
///
/// Every blind index in the store is `master.blind_index(context)`, derived from the master's
/// material directly rather than through a KEK, and this module rewraps `tenant_keks` and
/// touches none of them. So a rotation to a different SECRET leaves every stored index computed
/// under a key nothing derives any more, and a login by identifier stops finding its user.
///
/// This pins the property rather than the consequence, because the consequence is spread across
/// eight derivations in the repository and one of them changing would not be caught by testing
/// another. If this ever starts failing, either `derive` stopped keying off the secret alone or
/// something began carrying indexes across a rotation, and the module doc above needs revisiting.
#[test]
fn a_change_of_secret_changes_every_blind_index_and_a_change_of_id_does_not() {
    let context = ironauth_jose::Aad::builder()
        .text("user-identifier")
        .text("alice@example.com")
        .build();

    let before = MasterKey::derive("master-1", b"the-old-secret");
    let after_rotation = MasterKey::derive("master-2", b"the-new-secret");
    assert_ne!(
        before.blind_index(&context).as_bytes(),
        after_rotation.blind_index(&context).as_bytes(),
        "a rotation to a new secret orphans every stored blind index; the rekey does not rebuild \
         them, so identifier lookups stop finding existing rows"
    );

    // THE SAFE SHAPE, and the control: renaming the generation while keeping the secret leaves
    // every index intact, because `derive` keys off the secret alone.
    let renamed_only = MasterKey::derive("master-2", b"the-old-secret");
    assert_eq!(
        before.blind_index(&context).as_bytes(),
        renamed_only.blind_index(&context).as_bytes(),
        "changing only the id must leave lookups working, or the one rotation shape that is safe \
         today would not be"
    );
}
