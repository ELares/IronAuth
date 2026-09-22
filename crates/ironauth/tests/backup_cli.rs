// SPDX-License-Identifier: MIT OR Apache-2.0

//! `ironauth backup` and `ironauth restore`, end to end against a real Postgres (issue #153).
//!
//! The seal's integrity properties are tested in `ironauth-jose`. What is only reachable here
//! is the COMMAND: whether a backup of a seeded store restores into a fresh database with the
//! data intact, whether a tampered file or a wrong key REFUSES (the checksum-mismatch
//! criterion), and whether restoring over a live deployment is refused until the operator says
//! it out loud.

use std::io::Write;
use std::process::Command;
use std::time::SystemTime;

use ironauth_env::Env;
use sqlx::PgPool;

use ironauth_store::test_support::TestDatabase;
use ironauth_store::{CorrelationId, NewSession, SessionId};

/// Write a master-key secret to its own file and return the `ID:file:PATH` name.
fn secret(name: &str, secret: &str) -> String {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("backup-cli");
    std::fs::create_dir_all(&dir).expect("a temp directory");
    let path = dir.join(format!("{name}-{}.secret", std::process::id()));
    let mut file = std::fs::File::create(&path).expect("create the secret file");
    file.write_all(secret.as_bytes()).expect("write the secret");
    format!("master-1:file:{}", path.display())
}

/// Run `ironauth <verb> ...` and return (exit success, stdout, stderr).
fn run(args: &[&str]) -> (bool, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_ironauth"))
        .args(args)
        .output()
        .expect("run the ironauth binary");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn backup(dsn: &str, out: &str, key: &str) -> (bool, String, String) {
    run(&[
        "storage",
        "backup",
        "--url",
        dsn,
        "--out",
        out,
        "--master-key",
        key,
    ])
}

fn restore(dsn: &str, input: &str, key: &str, extra: &[&str]) -> (bool, String, String) {
    let mut args = vec![
        "storage",
        "restore",
        "--url",
        dsn,
        "--in",
        input,
        "--master-key",
        key,
    ];
    args.extend_from_slice(extra);
    run(&args)
}

/// A fresh, schema-less database on the same cluster, to restore into.
async fn fresh_database(name: &str) -> String {
    let owner_base = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must point at a Postgres superuser connection");
    let pool = PgPool::connect(&owner_base)
        .await
        .expect("connect as owner");
    sqlx::query(&format!("CREATE DATABASE \"{name}\""))
        .execute(&pool)
        .await
        .expect("create the fresh database");
    pool.close().await;
    let (before, _) = owner_base.rsplit_once('/').expect("a database in the URL");
    format!("{before}/{name}")
}

/// THE ACCEPTANCE CRITERION: restore from a backup yields a working instance with the data it
/// had — the migration ledger complete and every seeded row present.
#[tokio::test]
async fn restore_into_a_fresh_database_yields_the_backed_up_store() {
    let database = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0B0A_C001);
    let scope = database.seed_scope(&env).await;

    // A REAL session through the same path a login uses, so the restore's "sessions remain
    // valid" claim is about a row the validation path recognises, not a hand-shaped one.
    let session_id = SessionId::generate(&env, &scope);
    let absolute_expires_micros = 4_000_000_000_000_000_i64;
    database
        .store()
        .scoped(scope)
        .acting(database.test_actor(&env), CorrelationId::generate(&env))
        .sessions()
        .rotate(
            &env,
            &session_id,
            None,
            NewSession {
                impersonation: None,
                subject: "usr_restore_probe",
                auth_methods: "pwd",
                auth_time_micros: 1_700_000_000_000_000,
                idle_expires_micros: absolute_expires_micros,
                absolute_expires_micros,
                user_agent: None,
                peer_ip: None,
            },
        )
        .await
        .expect("create a session");

    let out = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("backup-{}.bin", std::process::id()))
        .display()
        .to_string();
    let key = secret("roundtrip", "the-backup-secret");

    let (ok, stdout, stderr) = backup(database.owner_url(), &out, &key);
    assert!(ok, "backup failed: {stderr}\n{stdout}");
    assert!(stdout.contains("encrypted logical backup"), "{stdout}");

    let target = fresh_database(&format!("backup_restore_target_{}", std::process::id())).await;
    let (ok, stdout, stderr) = restore(&target, &out, &key, &[]);
    assert!(ok, "restore failed: {stderr}\n{stdout}");

    let pool = PgPool::connect(&target)
        .await
        .expect("connect to the target");
    let source_ledger: i64 = sqlx::query_scalar("SELECT count(*) FROM _schema_migrations")
        .fetch_one(&pool)
        .await
        .expect("read the target ledger");
    let source_ledger_expected: i64 = {
        // The same ledger as the source, which migrated the full chain.
        sqlx::query_scalar("SELECT count(*) FROM _schema_migrations")
            .fetch_one(database.app_pool())
            .await
            .expect("read the source ledger")
    };
    assert_eq!(
        source_ledger, source_ledger_expected,
        "the ledger must come over whole"
    );
    let tenants: i64 = sqlx::query_scalar("SELECT count(*) FROM tenants")
        .fetch_one(&pool)
        .await
        .expect("read the target tenants");
    assert_eq!(tenants, 1, "the seeded tenant must survive");
    let environments: i64 = sqlx::query_scalar("SELECT count(*) FROM environments")
        .fetch_one(&pool)
        .await
        .expect("read the target environments");
    assert_eq!(environments, 1, "the seeded environment must survive");
    pool.close().await;

    // THE "SESSIONS REMAIN VALID" CRITERION: the session created before the backup is
    // read back on the RESTORED instance through the same validation path the runtime
    // uses (revoked/ended/superseded/expiry guards), and it resolves with the subject it
    // had. The restore did not reset, re-mint, or orphan it.
    let restored = ironauth_store::Store::connect(&target)
        .await
        .expect("connect to the restored store");
    let restored_session = restored
        .scoped(scope)
        .sessions()
        .get(&session_id, 1_700_000_000_000_000 + 3_600_000_000, IDLE_TTL)
        .await
        .expect("read the restored session");
    let session = restored_session.expect("the restored session must resolve as valid");
    assert_eq!(session.subject.as_str(), "usr_restore_probe");
    restored.close_pool_for_test().await;
}

/// An idle TTL inside the session's window, so the validation path reads it as live.
const IDLE_TTL: i64 = 3_600_000_000;

/// THE CHECKSUM-MISMATCH CRITERION AT THE COMMAND: a single flipped byte in the encrypted file
/// refuses, and the target is left untouched.
#[tokio::test]
async fn a_tampered_backup_refuses_and_leaves_the_target_untouched() {
    let database = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0B0A_C002);
    database.seed_scope(&env).await;

    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"));
    let out = dir
        .join(format!("backup-tamper-{}.bin", std::process::id()))
        .display()
        .to_string();
    let key = secret("tamper", "the-backup-secret");

    let (ok, _stdout, stderr) = backup(database.owner_url(), &out, &key);
    assert!(ok, "backup failed: {stderr}");

    let bytes = std::fs::read(&out).expect("read the backup");
    let last = bytes.len() - 1;
    let mut tampered = bytes.clone();
    tampered[last] ^= 0xFF;
    std::fs::write(&out, tampered).expect("write the tampered backup");

    let target = fresh_database(&format!("backup_tamper_target_{}", std::process::id())).await;
    let (ok, _stdout, stderr) = restore(&target, &out, &key, &[]);
    assert!(!ok, "a tampered backup MUST refuse");
    assert!(
        stderr.contains("REFUSING") && stderr.contains("did not verify"),
        "the refusal must say why: {stderr}"
    );

    let pool = PgPool::connect(&target)
        .await
        .expect("connect to the target");
    let ledgers: i64 =
        sqlx::query_scalar("SELECT count(*) FROM pg_class WHERE relname = '_schema_migrations'")
            .fetch_one(&pool)
            .await
            .expect("probe the target");
    assert_eq!(ledgers, 0, "nothing may be written by a refused restore");
    pool.close().await;
}

/// A wrong master key refuses before any connection is made (like the rekey guard, this part
/// must hold even against an unreachable database).
#[test]
fn a_wrong_key_refuses_before_the_database_is_touched() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"));
    let out = dir
        .join(format!("backup-wrongkey-{}.bin", std::process::id()))
        .display()
        .to_string();
    let key = secret("wrongkey-a", "the-backup-secret");
    let other = secret("wrongkey-b", "a-different-secret");

    // Seal a real backup without a database by exercising the CLI's own pipeline is not
    // possible, so prove the ordering instead: a file that is NOT a backup refuses for being
    // foreign, and the refusal happens before the DSN is opened (port 1: immediate failure).
    std::fs::write(&out, b"not a backup at all").expect("write a foreign file");
    let (ok, _stdout, stderr) =
        restore("postgres://ironauth@127.0.0.1:1/ironauth", &out, &key, &[]);
    assert!(!ok);
    assert!(
        stderr.contains("REFUSING") && stderr.contains("not an IronAuth backup"),
        "{stderr}"
    );

    // The key-mismatch half needs a real file, so back up a real database and restore with
    // the OTHER secret.
    let rt = tokio::runtime::Runtime::new().expect("a runtime");
    rt.block_on(async {
        let database = TestDatabase::start().await;
        let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0B0A_C003);
        database.seed_scope(&env).await;
        let (ok, _stdout, stderr) = backup(database.owner_url(), &out, &key);
        assert!(ok, "backup failed: {stderr}");
        let (ok, _stdout, stderr) =
            restore(database.owner_url(), &out, &other, &["--i-will-overwrite"]);
        assert!(!ok, "a wrong key MUST refuse");
        assert!(
            stderr.contains("REFUSING") && stderr.contains("did not verify"),
            "{stderr}"
        );
    });
}

/// Restoring over a live deployment is refused unless the operator says it out loud.
#[tokio::test]
async fn restoring_over_a_live_deployment_is_refused_without_acknowledgement() {
    let database = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0B0A_C004);
    database.seed_scope(&env).await;

    let out = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("backup-live-{}.bin", std::process::id()))
        .display()
        .to_string();
    let key = secret("live", "the-backup-secret");
    let (ok, _stdout, stderr) = backup(database.owner_url(), &out, &key);
    assert!(ok, "backup failed: {stderr}");

    let (ok, _stdout, stderr) = restore(database.owner_url(), &out, &key, &[]);
    assert!(!ok, "restoring over a live deployment MUST refuse");
    assert!(
        stderr.contains("already holds the schema"),
        "the refusal must name the guard: {stderr}"
    );
}
