// SPDX-License-Identifier: MIT OR Apache-2.0

//! The streaming import engine end to end against a real database (`DATABASE_URL`).
//!
//! Pins the issue #55 acceptance criteria at the persistence boundary: a streaming
//! import of many mixed-scheme records creates users through the audited admin path
//! (issue #52) with their PII sealed (issue #48); a foreign hash verifies and is
//! verify-then-rehashed to native Argon2id (the second read verifies natively); no
//! plaintext password is ever stored; a per-record failure does not abort the batch;
//! a re-import is idempotent (no duplicates); and an import into one tenant cannot
//! touch another.

use argon2::password_hash::{PasswordHash, PasswordVerifier};
use ironauth_env::Env;
use ironauth_import::scheme::{ForeignHash, firebase_stored};
use ironauth_import::{ImportContext, RecordOutcome, import_into_run, import_stream};
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CompletionOutcome, CorrelationId, MigrationKind, MigrationState, NewMigrationRun, Scope,
    UserId, UserListFilter, UserRecord, UserState,
};
use sqlx::Row;

/// A cheap bcrypt (cost 4) foreign hash for `password`.
fn bcrypt_hash(password: &str) -> String {
    bcrypt::hash_with_result(password, 4)
        .expect("bcrypt hash")
        .to_string()
}

/// A scrypt PHC foreign hash for `password`, at cheap parameters.
fn scrypt_hash(password: &str) -> String {
    use scrypt::password_hash::{PasswordHasher, SaltString};
    let salt = SaltString::encode_b64(b"scrypt-salt-x").expect("salt");
    let params = scrypt::Params::new(8, 8, 1, 32).expect("scrypt params");
    scrypt::Scrypt
        .hash_password_customized(password.as_bytes(), None, None, params, &salt)
        .expect("scrypt hash")
        .to_string()
}

/// A PBKDF2 PHC foreign hash for `password`, at cheap iteration count.
fn pbkdf2_hash(password: &str) -> String {
    use pbkdf2::password_hash::{PasswordHasher, SaltString};
    let salt = SaltString::encode_b64(b"pbkdf2-salt-x").expect("salt");
    let params = pbkdf2::Params {
        rounds: 1000,
        output_length: 32,
    };
    pbkdf2::Pbkdf2
        .hash_password_customized(
            password.as_bytes(),
            Some(pbkdf2::Algorithm::Pbkdf2Sha256.ident()),
            None,
            params,
            &salt,
        )
        .expect("pbkdf2 hash")
        .to_string()
}

/// An Argon2 PHC foreign hash for `password` (verified through the foreign path,
/// then rehashed to a FRESH native Argon2id verifier at import parameters).
fn argon2_hash(password: &str) -> String {
    use argon2::password_hash::{PasswordHasher, SaltString};
    let salt = SaltString::encode_b64(b"argon2-salt-yy").expect("salt");
    argon2::Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("argon2 hash")
        .to_string()
}

/// The published Firebase modified-scrypt vector (password `user1password`),
/// serialized into the canonical `$fbscrypt$` storage form.
fn firebase_hash_vector() -> String {
    firebase_stored(
        14,
        8,
        "Bw==",
        "jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==",
        "42xEC+ixf3L2lw==",
        "lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ==",
    )
}

fn record_line(identifier: &str, password_hash: &str) -> String {
    format!(r#"{{"identifier":"{identifier}","password_hash":"{password_hash}"}}"#)
}

fn ctx<'a>(db: &'a TestDatabase, env: &'a Env, scope: Scope) -> ImportContext<'a> {
    ImportContext {
        store: db.store(),
        scope,
        env,
        actor: db.test_actor(env),
    }
}

/// Collect every record outcome while running an import.
async fn run_import(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    lines: Vec<String>,
) -> (ironauth_import::ImportReport, Vec<RecordOutcome>) {
    let context = ctx(db, env, scope);
    let mut outcomes = Vec::new();
    let report = import_stream(&context, lines, |outcome| outcomes.push(outcome)).await;
    (report, outcomes)
}

async fn count_users(db: &TestDatabase, scope: Scope) -> usize {
    db.store()
        .scoped(scope)
        .users()
        .list(UserListFilter::default(), 1000, None)
        .await
        .expect("list users")
        .len()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test]
async fn streaming_import_of_mixed_schemes_creates_every_user() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x55);
    let scope = db.seed_scope(&env).await;

    let mut lines = Vec::new();
    // A batch of bcrypt users to exercise the streaming path, plus one of every
    // other supported scheme.
    for i in 0..25 {
        lines.push(record_line(
            &format!("bcrypt-{i}@x.test"),
            &bcrypt_hash("pw"),
        ));
    }
    lines.push(record_line("scrypt@x.test", &scrypt_hash("pw")));
    lines.push(record_line("pbkdf2@x.test", &pbkdf2_hash("pw")));
    lines.push(record_line("argon2@x.test", &argon2_hash("pw")));
    lines.push(record_line("firebase@x.test", &firebase_hash_vector()));
    // A credential-less record (no hash) is valid too.
    lines.push(r#"{"identifier":"no-cred@x.test"}"#.to_owned());
    // A blank separator line is skipped, not counted.
    lines.push(String::new());

    // 25 bcrypt + scrypt + pbkdf2 + argon2 + firebase + one credential-less = 30.
    let expected: u64 = 30;
    let (report, _outcomes) = run_import(&db, &env, scope, lines).await;
    assert_eq!(report.processed, expected, "blank line not counted");
    assert_eq!(report.succeeded, expected);
    assert_eq!(report.failed, 0);
    assert_eq!(report.skipped, 0);
    assert_eq!(count_users(&db, scope).await, 30);
}

#[tokio::test]
async fn imported_bcrypt_user_logs_in_then_is_rehashed_to_argon2id() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x56);
    let scope = db.seed_scope(&env).await;

    let identifier = "migrated@x.test";
    let password = "correct horse battery staple";
    let foreign = bcrypt_hash(password);
    let (report, _) = run_import(&db, &env, scope, vec![record_line(identifier, &foreign)]).await;
    assert_eq!(report.succeeded, 1);

    // FIRST login: the native verifier is the unusable sentinel, so the foreign hash
    // is what authenticates. This mirrors the login path exactly.
    let record = login_lookup(&db, scope, identifier).await;
    assert!(
        !native_verify(&record, password),
        "native verifier is the unusable import sentinel before first login"
    );
    let foreign_hash = record
        .foreign_password_hash
        .as_deref()
        .expect("foreign hash present before first login");
    assert_eq!(record.foreign_password_algo.as_deref(), Some("bcrypt"));
    assert!(
        ForeignHash::parse(foreign_hash)
            .expect("parse foreign")
            .verify(password.as_bytes()),
        "the old password verifies against the foreign bcrypt hash"
    );

    // The verify-then-rehash landing: write a fresh native Argon2id verifier and
    // retire the foreign hash, exactly as the login handler does on success.
    let native = argon2_hash(password);
    let upgraded = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .users()
        .upgrade_foreign_password(&env, &record.id, &native)
        .await
        .expect("upgrade");
    assert!(upgraded, "the first upgrade flips the row");

    // SECOND login: the native Argon2id verifier authenticates and the foreign hash
    // is gone.
    let record2 = login_lookup(&db, scope, identifier).await;
    assert!(
        record2.foreign_password_hash.is_none(),
        "the foreign hash is retired after rehash"
    );
    assert!(record2.foreign_password_algo.is_none());
    assert!(
        native_verify(&record2, password),
        "the second login verifies against Argon2id only"
    );

    // A second upgrade is a benign no-op (there is no foreign hash left): it flips no
    // row and writes no audit row, so concurrent logins race safely.
    let again = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .users()
        .upgrade_foreign_password(&env, &record.id, &native)
        .await
        .expect("second upgrade");
    assert!(!again, "a repeat upgrade is a no-op");
}

/// Look up a user for login by identifier, expecting it to exist.
async fn login_lookup(db: &TestDatabase, scope: Scope, identifier: &str) -> UserRecord {
    db.store()
        .scoped(scope)
        .users()
        .by_identifier(identifier)
        .await
        .expect("by_identifier")
        .expect("user exists")
}

/// Verify a password against the record's NATIVE Argon2id verifier (false for the
/// unusable sentinel).
fn native_verify(record: &UserRecord, password: &str) -> bool {
    match PasswordHash::new(&record.password_hash) {
        Ok(parsed) => argon2::Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

#[tokio::test]
async fn a_dump_carries_no_plaintext_password_and_seals_the_identifier() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x57);
    let scope = db.seed_scope(&env).await;

    let identifier = "probe@x.test";
    let password = "super-secret-plaintext-9271";
    let (report, outcomes) = run_import(
        &db,
        &env,
        scope,
        vec![record_line(identifier, &bcrypt_hash(password))],
    )
    .await;
    assert_eq!(report.succeeded, 1);
    let RecordOutcome::Created { id, .. } = &outcomes[0] else {
        panic!("expected a create outcome");
    };

    // The raw row a stolen backup would expose.
    let row = sqlx::query(
        "SELECT foreign_password_hash, foreign_password_algo, identifier_sealed \
         FROM users WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
    )
    .bind(id)
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("dump row");
    let foreign_hash: String = row.get("foreign_password_hash");
    let algo: String = row.get("foreign_password_algo");
    let identifier_sealed: Vec<u8> = row.get("identifier_sealed");

    // The stored foreign hash is a one-way bcrypt verifier, NEVER the plaintext.
    assert!(
        !foreign_hash.contains(password),
        "the stored foreign hash is not the plaintext password"
    );
    assert!(
        foreign_hash.starts_with("$2"),
        "a bcrypt verifier is stored"
    );
    assert_eq!(algo, "bcrypt");
    // The login handle is sealed (issue #48): the plaintext is not in the dump.
    assert!(
        !contains(&identifier_sealed, identifier.as_bytes()),
        "the sealed identifier does not contain the plaintext handle"
    );
}

#[tokio::test]
async fn a_bad_record_does_not_abort_the_batch() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x58);
    let scope = db.seed_scope(&env).await;

    let over_cost = format!("$2b$31${}", "a".repeat(53));
    let lines = vec![
        record_line("ok-a@x.test", &bcrypt_hash("pw")),
        record_line("dos@x.test", &over_cost), // rejected at import (DoS bound)
        "{ not json".to_owned(),
        record_line("ok-b@x.test", &bcrypt_hash("pw")),
    ];
    let (report, _) = run_import(&db, &env, scope, lines).await;
    assert_eq!(report.processed, 4);
    assert_eq!(report.succeeded, 2, "both good records past the failures");
    assert_eq!(report.failed, 2, "the DoS-cost and the malformed line");
    assert_eq!(count_users(&db, scope).await, 2);
}

#[tokio::test]
async fn reimport_is_idempotent_and_creates_no_duplicates() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x59);
    let scope = db.seed_scope(&env).await;

    let lines = vec![
        record_line("dup-a@x.test", &bcrypt_hash("pw")),
        record_line("dup-b@x.test", &bcrypt_hash("pw")),
    ];
    let (first, _) = run_import(&db, &env, scope, lines.clone()).await;
    assert_eq!(first.succeeded, 2);

    // Re-run the SAME import: every record is a skip (the login-handle unique
    // constraint rejects the duplicate), none fail, and no second row is created.
    let (second, outcomes) = run_import(&db, &env, scope, lines).await;
    assert_eq!(second.succeeded, 0);
    assert_eq!(second.skipped, 2, "both are idempotent skips");
    assert_eq!(second.failed, 0);
    assert!(
        outcomes
            .iter()
            .all(|o| matches!(o, RecordOutcome::Skipped { .. })),
        "every re-import outcome is a skip"
    );
    assert_eq!(count_users(&db, scope).await, 2, "no duplicates");
}

#[tokio::test]
async fn import_into_one_tenant_never_touches_another() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5a);
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;

    // Import two users into tenant A.
    let (report, _) = run_import(
        &db,
        &env,
        scope_a,
        vec![
            record_line("a-1@x.test", &bcrypt_hash("pw")),
            record_line("a-2@x.test", &bcrypt_hash("pw")),
        ],
    )
    .await;
    assert_eq!(report.succeeded, 2);

    // Tenant B is untouched.
    assert_eq!(count_users(&db, scope_b).await, 0, "tenant B has no users");
    assert_eq!(count_users(&db, scope_a).await, 2);

    // A record carrying an id minted in tenant B is REJECTED when importing into
    // tenant A (scope confinement), never a cross-tenant create.
    let foreign_id = UserId::generate(&env, &scope_b);
    let line = format!(
        r#"{{"identifier":"intruder@x.test","id":"{foreign_id}","password_hash":"{}"}}"#,
        bcrypt_hash("pw")
    );
    let (report, outcomes) = run_import(&db, &env, scope_a, vec![line]).await;
    assert_eq!(report.failed, 1, "the cross-scope id is rejected");
    assert_eq!(report.succeeded, 0);
    assert!(matches!(outcomes[0], RecordOutcome::Failed(_)));
    assert_eq!(count_users(&db, scope_b).await, 0, "tenant B still empty");
}

#[tokio::test]
async fn imported_states_and_claims_round_trip() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5b);
    let scope = db.seed_scope(&env).await;

    let lines = vec![
        r#"{"identifier":"blocked@x.test","state":"blocked"}"#.to_owned(),
        r#"{"identifier":"claimful@x.test","claims":{"email":"claimful@x.test","email_verified":true}}"#.to_owned(),
    ];
    let (report, _) = run_import(&db, &env, scope, lines).await;
    assert_eq!(report.succeeded, 2);

    let blocked = login_lookup(&db, scope, "blocked@x.test").await;
    assert_eq!(blocked.state, UserState::Blocked);
    assert!(
        !blocked.state.can_authenticate(),
        "an imported blocked user is fenced from login"
    );

    let claims = db
        .store()
        .scoped(scope)
        .users()
        .by_identifier("claimful@x.test")
        .await
        .expect("lookup")
        .expect("exists");
    let stored = db
        .store()
        .scoped(scope)
        .users()
        .claims_for_subject(&claims.id.to_string())
        .await
        .expect("claims")
        .expect("some");
    assert!(
        stored.contains("email_verified"),
        "claims round-trip: {stored}"
    );
}

/// Wrapping a bulk import in the migration state machine (issue #59): the import runs
/// into a run, every record is accounted, and when the declared source total matches
/// the machine COMPLETES. An off-by-one source total instead BLOCKS on the count
/// invariant, so an import that does not reconcile with its source cannot declare
/// victory.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn a_bulk_import_wrapped_in_the_migration_machine_gates_on_the_count_invariant() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x59);
    let scope = db.seed_scope(&env).await;
    let store = db.store();

    // Three well-formed source lines and one unparseable line: four processed records
    // (three created, one failed), all accounted.
    let lines = vec![
        record_line("alice@example.test", &argon2_hash("pw-a")),
        record_line("bob@example.test", &argon2_hash("pw-b")),
        record_line("carol@example.test", &argon2_hash("pw-c")),
        "{ this is not valid json".to_string(),
    ];
    let source_total = i64::try_from(lines.len()).expect("source total fits");

    // Create a run declaring the source total, drive it to running, and import into it.
    let run = store
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .migration_runs()
        .create(
            &env,
            NewMigrationRun {
                kind: MigrationKind::BulkImport,
                source_total,
                backfill_expected: 0,
                subject_ref: Some("import:2026-07-15"),
            },
            1_000_000,
        )
        .await
        .expect("create run");
    for state in [MigrationState::Validating, MigrationState::Running] {
        store
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .migration_runs()
            .transition(&env, &run, state)
            .await
            .expect("transition");
    }

    let context = ctx(&db, &env, scope);
    let report = import_into_run(&context, &run, lines)
        .await
        .expect("import into run");
    assert_eq!(report.processed, 4);
    assert_eq!(report.succeeded, 3);
    assert_eq!(report.failed, 1);

    // The tallies re-derive live: 3 imported + 1 failed == 4 accounted == source_total.
    let tallies = store
        .scoped(scope)
        .migration_runs()
        .tallies(&run)
        .await
        .expect("tallies");
    assert_eq!(tallies.imported, 3);
    assert_eq!(tallies.failed, 1);
    assert_eq!(tallies.accounted, source_total);

    // With the source total matching, the wrapped import COMPLETES.
    store
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .migration_runs()
        .transition(&env, &run, MigrationState::Reconciling)
        .await
        .expect("-> reconciling");
    let outcome = store
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .migration_runs()
        .try_complete(&env, &run)
        .await
        .expect("try_complete");
    assert_eq!(outcome, CompletionOutcome::Completed);

    // A SECOND run over the same source but with an inflated source total (an injected
    // off-by-one) is BLOCKED by the count invariant: it cannot complete.
    let run2 = store
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .migration_runs()
        .create(
            &env,
            NewMigrationRun {
                kind: MigrationKind::BulkImport,
                source_total: source_total + 1,
                backfill_expected: 0,
                subject_ref: None,
            },
            1_000_000,
        )
        .await
        .expect("create run2");
    for state in [MigrationState::Validating, MigrationState::Running] {
        store
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .migration_runs()
            .transition(&env, &run2, state)
            .await
            .expect("transition");
    }
    // Re-import the SAME lines (idempotent: created become skipped), still four accounted.
    let lines2 = vec![
        record_line("alice@example.test", &argon2_hash("pw-a")),
        record_line("bob@example.test", &argon2_hash("pw-b")),
        record_line("carol@example.test", &argon2_hash("pw-c")),
        "{ this is not valid json".to_string(),
    ];
    import_into_run(&ctx(&db, &env, scope), &run2, lines2)
        .await
        .expect("import into run2");
    store
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .migration_runs()
        .transition(&env, &run2, MigrationState::Reconciling)
        .await
        .expect("-> reconciling");
    let blocked = store
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .migration_runs()
        .try_complete(&env, &run2)
        .await
        .expect("try_complete");
    assert!(
        matches!(blocked, CompletionOutcome::Blocked(_)),
        "an inflated source total must block completion: {blocked:?}"
    );
    assert_eq!(
        store
            .scoped(scope)
            .migration_runs()
            .get(&run2)
            .await
            .expect("get")
            .state,
        MigrationState::Reconciling
    );
}
