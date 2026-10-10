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
/// had - the migration ledger complete and every seeded row present.
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
    let target_app = restored_role_url(database.app_url(), &target);
    let restored = ironauth_store::Store::connect(&target_app)
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

fn restored_role_url(source_role_url: &str, target_owner_url: &str) -> String {
    let (_, target_name) = target_owner_url.rsplit_once('/').unwrap();
    let (role_base, _) = source_role_url.rsplit_once('/').unwrap();
    format!("{role_base}/{target_name}")
}

struct IdentityBackupFixture {
    scope: ironauth_store::Scope,
    client: ironauth_store::ClientId,
    legacy_user: ironauth_store::UserId,
    pairwise_user: ironauth_store::UserId,
    unbound_user: ironauth_store::UserId,
    salt: ironauth_store::PairwiseSaltMaterial,
    pairwise_subject: String,
    unbound_subject: String,
    policy: ironauth_store::ClientSubjectPolicySnapshot,
    receipt: ironauth_store::ClientSubjectHistoryReport,
}

fn identity_state(store: ironauth_store::Store, env: &Env) -> ironauth_oidc::OidcState {
    let base = "https://restore.example.test";
    let registry =
        ironauth_oidc::IssuerRegistry::new(base, ironauth_oidc::JwksCacheWindow::new(600).unwrap());
    ironauth_oidc::OidcState::new(
        store,
        env.clone(),
        std::sync::Arc::new(registry),
        &ironauth_config::OidcConfig::default(),
        base,
    )
}

async fn activate_reconciled_pairwise(
    db: &TestDatabase,
    env: &Env,
    scope: ironauth_store::Scope,
    client: ironauth_store::ClientId,
    legacy_user: ironauth_store::UserId,
) -> ironauth_store::ClientSubjectPolicySnapshot {
    let actor = db.test_actor(env);
    sqlx::query("UPDATE clients SET subject_history_ready=false WHERE id=$1")
        .bind(client.to_string())
        .execute(db.owner_pool())
        .await
        .unwrap();
    let initial = db
        .store()
        .scoped(scope)
        .clients()
        .subject_policy(&client)
        .await
        .unwrap();
    let control = db
        .control_store()
        .management()
        .acting(actor, CorrelationId::generate(env));
    let history = control.client_subject_history(scope);
    history
        .import_public(env, &initial, &[legacy_user])
        .await
        .unwrap();
    history
        .reconcile(
            env,
            &initial,
            &ironauth_store::ClientSubjectHistoryAttestation {
                evidence_sha256: "a".repeat(64),
                legacy_issuers_stopped: true,
                external_history_reconciled: true,
                public_identifiers_retained: true,
            },
        )
        .await
        .unwrap();
    let ready = db
        .store()
        .scoped(scope)
        .clients()
        .subject_policy(&client)
        .await
        .unwrap();
    control
        .client_subject_policies(scope)
        .set(
            env,
            &ready,
            &ironauth_store::ClientSubjectPolicy::Pairwise {
                sector_identifier: "application.example.test".to_owned(),
                sector_identifier_uri: Some(
                    "https://application.example.test/sector.json".to_owned(),
                ),
            },
        )
        .await
        .unwrap()
}

async fn seed_identity_backup(
    db: &TestDatabase,
    env: &Env,
    scope: ironauth_store::Scope,
) -> IdentityBackupFixture {
    let actor = db.test_actor(env);
    let acting = db
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(env));
    let client = acting
        .clients()
        .create(env, "identity backup")
        .await
        .unwrap();
    let legacy_user = acting
        .users()
        .register(env, "legacy@example.test", "hash", None)
        .await
        .unwrap();
    let pairwise_user = acting
        .users()
        .register(env, "pairwise@example.test", "hash", None)
        .await
        .unwrap();
    let unbound_user = acting
        .users()
        .register(env, "unbound@example.test", "hash", None)
        .await
        .unwrap();
    let policy = activate_reconciled_pairwise(db, env, scope, client, legacy_user).await;
    let state = identity_state(db.store().clone(), env);
    let pairwise_subject = state
        .resolve_registered_subject(scope, &client.to_string(), &pairwise_user.to_string())
        .await
        .unwrap();
    assert_ne!(pairwise_subject, pairwise_user.to_string());
    let salt = db
        .store()
        .scoped(scope)
        .envelope()
        .pairwise_salt()
        .await
        .unwrap();
    // Preserve the pre-rotation identity through re-encryption and backup/restore.
    acting
        .envelope()
        .rotate_dek(env, &db.master_key())
        .await
        .unwrap();
    acting
        .envelope()
        .reencrypt_secret(
            env,
            &db.master_key(),
            ironauth_store::PAIRWISE_SUBJECT_SALT_PURPOSE,
        )
        .await
        .unwrap();
    acting
        .envelope()
        .rotate_kek(env, &db.master_key())
        .await
        .unwrap();
    let unbound_subject = ironauth_oidc::resolve_subject(
        &ironauth_oidc::SubjectConfig::pairwise("application.example.test"),
        &unbound_user.to_string(),
        &ironauth_oidc::PairwiseSalt::new(salt.as_bytes().to_vec()),
    );
    assert_eq!(
        db.store()
            .scoped(scope)
            .clients()
            .subject_binding(&client, &unbound_user)
            .await
            .unwrap(),
        None
    );
    let receipt = db
        .control_store()
        .management()
        .client_subject_history(scope)
        .get(&client)
        .await
        .unwrap();
    IdentityBackupFixture {
        scope,
        client,
        legacy_user,
        pairwise_user,
        unbound_user,
        salt,
        pairwise_subject,
        unbound_subject,
        policy,
        receipt,
    }
}

async fn assert_restored_identity(
    store: &ironauth_store::Store,
    control: &ironauth_store::Store,
    state: &ironauth_oidc::OidcState,
    fixture: &IdentityBackupFixture,
) {
    let f = fixture;
    assert_eq!(
        store
            .scoped(f.scope)
            .envelope()
            .pairwise_salt()
            .await
            .unwrap(),
        f.salt
    );
    assert_eq!(
        store
            .scoped(f.scope)
            .clients()
            .subject_policy(&f.client)
            .await
            .unwrap(),
        f.policy
    );
    assert_eq!(
        control
            .management()
            .client_subject_history(f.scope)
            .get(&f.client)
            .await
            .unwrap(),
        f.receipt
    );
    for (user, expected) in [
        (f.legacy_user, f.legacy_user.to_string()),
        (f.pairwise_user, f.pairwise_subject.clone()),
        (f.unbound_user, f.unbound_subject.clone()),
    ] {
        assert_eq!(
            state
                .resolve_registered_subject(f.scope, &f.client.to_string(), &user.to_string())
                .await
                .unwrap(),
            expected
        );
        assert_eq!(
            store
                .scoped(f.scope)
                .clients()
                .subject_binding(&f.client, &user)
                .await
                .unwrap(),
            Some(expected)
        );
    }
}

/// The actual encrypted CLI artifact must recover identity, including derivation
/// for an account with no pre-existing binding. Reading only cached bindings
/// would hide a lost salt or unavailable envelope master key.
#[tokio::test]
async fn encrypted_restore_preserves_pairwise_material_bindings_and_reconciliation_receipts() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let a = db.seed_scope(&env).await;
    let b = ironauth_store::Scope::new(a.tenant(), db.seed_environment(&env, a.tenant()).await);
    let c = db.seed_scope(&env).await;
    let mut fixtures = Vec::new();
    for scope in [a, b, c] {
        fixtures.push(seed_identity_backup(&db, &env, scope).await);
    }
    assert_ne!(fixtures[0].salt, fixtures[1].salt);
    assert_ne!(fixtures[0].salt, fixtures[2].salt);
    let out = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("pairwise-backup-{}.bin", std::process::id()));
    let key = secret(
        "pairwise-roundtrip",
        "fixture-backup-key-distinct-from-envelope-master",
    );
    let (ok, _, stderr) = backup(db.owner_url(), out.to_str().unwrap(), &key);
    assert!(ok, "backup failed: {stderr}");
    // Dispose of source serving pools; recovery uses entirely new connections,
    // a different database and a fresh OIDC identity resolver.
    db.store().close_pool_for_test().await;
    db.control_store().close_pool_for_test().await;
    let target = fresh_database(&format!("pairwise_restore_target_{}", std::process::id())).await;
    let (ok, _, stderr) = restore(&target, out.to_str().unwrap(), &key, &[]);
    assert!(ok, "restore failed: {stderr}");
    let target_app = restored_role_url(db.app_url(), &target);
    assert_identity_privileges(&target).await;
    let no_master = ironauth_store::Store::connect(&target_app).await.unwrap();
    let fresh = identity_state(no_master.clone(), &env);
    let without_master = fresh
        .resolve_registered_subject(
            a,
            &fixtures[0].client.to_string(),
            &fixtures[0].unbound_user.to_string(),
        )
        .await;
    assert!(
        matches!(without_master, Err(ironauth_store::StoreError::Encryption)),
        "unbound identity without envelope master must fail closed: {without_master:?}"
    );
    no_master.close_pool_for_test().await;
    let wrong_master = ironauth_store::Store::connect(&target_app)
        .await
        .unwrap()
        .with_master_key(std::sync::Arc::new(ironauth_jose::MasterKey::generate(
            "wrong-restored-master",
            env.entropy(),
        )));
    assert!(matches!(
        identity_state(wrong_master.clone(), &env)
            .resolve_registered_subject(
                a,
                &fixtures[0].client.to_string(),
                &fixtures[0].unbound_user.to_string(),
            )
            .await,
        Err(ironauth_store::StoreError::Encryption)
    ));
    assert_eq!(
        wrong_master
            .scoped(a)
            .clients()
            .subject_binding(&fixtures[0].client, &fixtures[0].unbound_user)
            .await
            .unwrap(),
        None
    );
    wrong_master.close_pool_for_test().await;
    let restored = ironauth_store::Store::connect(&target_app)
        .await
        .unwrap()
        .with_master_key(db.master_key());
    let target_control = restored_role_url(db.control_url(), &target);
    let restored_control = ironauth_store::Store::connect(&target_control)
        .await
        .unwrap();
    let state = identity_state(restored.clone(), &env);
    for fixture in &fixtures {
        assert_restored_identity(&restored, &restored_control, &state, fixture).await;
    }
    assert!(matches!(
        restored
            .scoped(b)
            .clients()
            .subject_policy(&fixtures[0].client)
            .await,
        Err(ironauth_store::StoreError::NotFound)
    ));
    // A second independent pool must observe the newly minted post-restore binding.
    let second = ironauth_store::Store::connect(&target_app)
        .await
        .unwrap()
        .with_master_key(db.master_key());
    let second_state = identity_state(second.clone(), &env);
    for fixture in &fixtures {
        assert_restored_identity(&second, &restored_control, &second_state, fixture).await;
    }
    restored.close_pool_for_test().await;
    second.close_pool_for_test().await;
    restored_control.close_pool_for_test().await;
    std::fs::remove_file(out).unwrap();
}

/// Database ACLs remain narrow as well as usable after restoration.
async fn assert_identity_privileges(target: &str) {
    let owner = PgPool::connect(target).await.unwrap();
    for role in ["ironauth_app", "ironauth_control"] {
        for (privilege, expected) in [
            ("SELECT", true),
            ("INSERT", true),
            ("UPDATE", false),
            ("DELETE", false),
        ] {
            let actual: bool =
                sqlx::query_scalar("SELECT has_table_privilege($1, 'client_subject_bindings', $2)")
                    .bind(role)
                    .bind(privilege)
                    .fetch_one(&owner)
                    .await
                    .unwrap();
            assert_eq!(actual, expected, "{role} binding {privilege}");
        }
        let readiness: bool = sqlx::query_scalar(
            "SELECT has_column_privilege($1, 'clients', 'subject_history_ready', 'UPDATE')",
        )
        .bind(role)
        .fetch_one(&owner)
        .await
        .unwrap();
        assert_eq!(readiness, role == "ironauth_control");
    }
    let (enabled, forced): (bool, bool) = sqlx::query_as(
        "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid='client_subject_bindings'::regclass"
    ).fetch_one(&owner).await.unwrap();
    assert!(enabled && forced);
    owner.close().await;
}

/// Missing out-of-band roles refuse the transaction instead of silently losing ACLs.
#[tokio::test]
async fn missing_destination_role_rolls_back_restore_and_can_be_retried() {
    let db = TestDatabase::start().await;
    let role = format!("restore_acl_probe_{}", std::process::id());
    db.execute_owner_sql(&format!("CREATE ROLE {role} NOLOGIN"))
        .await;
    db.execute_owner_sql(&format!("GRANT SELECT ON clients TO {role}"))
        .await;
    let out = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("acl-backup-{}.bin", std::process::id()));
    let key = secret("missing-role", "fixture-backup-key");
    let (ok, _, stderr) = backup(db.owner_url(), out.to_str().unwrap(), &key);
    assert!(ok, "backup failed: {stderr}");
    db.execute_owner_sql(&format!("REVOKE SELECT ON clients FROM {role}"))
        .await;
    db.execute_owner_sql(&format!("DROP ROLE {role}")).await;
    let target = fresh_database(&format!("acl_restore_target_{}", std::process::id())).await;
    let (ok, _, stderr) = restore(&target, out.to_str().unwrap(), &key, &[]);
    assert!(!ok, "a destination missing a referenced role must refuse");
    assert!(
        stderr.contains(&format!("role \"{role}\" does not exist")),
        "{stderr}"
    );
    let pool = PgPool::connect(&target).await.unwrap();
    let tables: i64 =
        sqlx::query_scalar("SELECT count(*) FROM pg_tables WHERE schemaname='public'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(tables, 0, "failed restore must roll back every table");
    db.execute_owner_sql(&format!("CREATE ROLE {role} NOLOGIN"))
        .await;
    let (ok, _, stderr) = restore(&target, out.to_str().unwrap(), &key, &[]);
    assert!(ok, "restore after role provisioning failed: {stderr}");
    let allowed: bool = sqlx::query_scalar("SELECT has_table_privilege($1, 'clients', 'SELECT')")
        .bind(&role)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(allowed);
    sqlx::query(&format!("REVOKE SELECT ON clients FROM {role}"))
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    db.execute_owner_sql(&format!("DROP ROLE {role}")).await;
    std::fs::remove_file(out).unwrap();
}
