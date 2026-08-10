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
    CompletionOutcome, CorrelationId, InvariantKind, MigrationKind, MigrationState,
    NewMigrationRun, Scope, UserId, UserListFilter, UserRecord, UserState,
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
    let mut outcomes = ironauth_import::CollectOutcomes::default();
    let report = import_stream(&context, lines, &mut outcomes)
        .await
        .expect("the collecting observer never fails");
    (report, outcomes.0)
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
    // SHA-crypt and the LDAP digests (issue #55, criterion 3). These are the POSITIVE
    // control for the two schemes added last: the out-of-bounds sweep below refuses a
    // SHA-crypt record, but `Unrecognized` is also a refusal, so without a record that
    // IMPORTS this file could not tell "bounded correctly" from "not supported at all".
    lines.push(record_line(
        "shacrypt5@x.test",
        "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5",
    ));
    lines.push(record_line(
        "shacrypt6@x.test",
        "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLi\
BFdcbYEdFCoEOfaS35inz1",
    ));
    lines.push(record_line(
        "ldap-sha@x.test",
        "{SHA}q/eq1kOINtvlJqojGr3i0O73TUI=",
    ));
    lines.push(record_line(
        "ldap-ssha512@x.test",
        "{SSHA512}JodACNxpTAd0DIaHvcP5uCTsFi8Ofk8+LKZP7HPwd1qWYfjZOyY7mLbLRdPMXheod9+qp\
NFl7/Jgi5pTlPu+dWEtbmluZXRlZW4tYnl0ZS1zbHQ=",
    ));
    // A credential-less record (no hash) is valid too.
    lines.push(r#"{"identifier":"no-cred@x.test"}"#.to_owned());
    // A blank separator line is skipped, not counted.
    lines.push(String::new());

    // 25 bcrypt + scrypt + pbkdf2 + argon2 + firebase + 2 sha-crypt + 2 ldap
    // + one credential-less = 34.
    let expected: u64 = 34;
    let (report, _outcomes) = run_import(&db, &env, scope, lines).await;
    assert_eq!(report.processed, expected, "blank line not counted");
    assert_eq!(report.succeeded, expected);
    assert_eq!(report.failed, 0);
    assert_eq!(report.skipped, 0);
    assert_eq!(count_users(&db, scope).await, 34);
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

/// Wrapping a bulk import in the migration state machine (issue #59): every record is
/// accounted, and BOTH gates are real.
///
/// * A run whose source carried a FAILED record has its count invariant satisfied (the
///   failure is accounted, not dropped) and is BLOCKED on CONSISTENCY, because a failed
///   record is written `consistent = false` and is therefore READABLE on the violations
///   surface. Writing it `consistent = true` (which the first cut did) made the
///   consistency invariant vacuous for every bulk import: the run reported `failed = 1`
///   while both violation queries returned an empty page, so issue #55's "every failure
///   reported with its record identity" was unmet on the only surface that reports.
/// * A run whose declared source total is one too high is BLOCKED on COUNT, so an import
///   that does not reconcile with its source cannot declare victory.
/// * And a run with no failure and a matching total COMPLETES, which is the control that
///   keeps the two blocks above from being satisfied by a gate that refuses everything.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn a_bulk_import_wrapped_in_the_migration_machine_gates_on_its_invariants() {
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
    assert_eq!(report.records.processed, 4);
    assert_eq!(report.records.succeeded, 3);
    assert_eq!(report.records.failed, 1);
    // A first pass over a source with four distinct keys writes four ledger rows and
    // dedups nothing.
    assert_eq!(report.ledger_written, 4, "{report:?}");
    assert_eq!(report.ledger_deduped, 0, "{report:?}");

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
    assert_eq!(
        tallies.inconsistent, 1,
        "the failed record is written INCONSISTENT, which is what puts it on the \
         violations surface: {tallies:?}"
    );

    // And it is genuinely READABLE there, with its reason. This is the assertion the
    // vacuous `consistent: true` passed while the surface returned an empty page.
    let offenders = store
        .scoped(scope)
        .migration_runs()
        .list_violations(&run, InvariantKind::Consistency, 10, None)
        .await
        .expect("violations");
    assert_eq!(offenders.len(), 1, "{offenders:?}");
    let detail = offenders[0].detail.as_deref().unwrap_or_default();
    assert!(
        detail.contains("parse error"),
        "the violation carries the per-record reason: {detail}"
    );

    // The count invariant IS satisfied (nothing was dropped), and completion is blocked
    // by CONSISTENCY alone: a run that imported a bad record has not reconciled.
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
    let CompletionOutcome::Blocked(violated) = outcome else {
        panic!("a run holding a failed record must not complete: {outcome:?}");
    };
    let blocked: Vec<InvariantKind> = violated.iter().map(|eval| eval.kind).collect();
    assert_eq!(
        blocked,
        vec![InvariantKind::Consistency],
        "only consistency blocks: the failure was accounted, so the count reconciles"
    );

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
    let CompletionOutcome::Blocked(violated) = blocked else {
        panic!("an inflated source total must block completion: {blocked:?}");
    };
    assert!(
        violated
            .iter()
            .any(|eval| eval.kind == InvariantKind::Count),
        "the COUNT invariant is what an inflated source total violates: {violated:?}"
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

    // ---- run 3: the anti-vacuity control -----------------------------------------
    // A source with NO failed record and a matching declared total still COMPLETES, so
    // neither block above is a gate that refuses everything. Every record here is an
    // idempotent skip (the users exist from run 1), which is still an accounted,
    // consistent record.
    let clean = vec![
        record_line("alice@example.test", &argon2_hash("pw-a")),
        record_line("bob@example.test", &argon2_hash("pw-b")),
        record_line("carol@example.test", &argon2_hash("pw-c")),
    ];
    let clean_total = i64::try_from(clean.len()).expect("fits");
    let run3 = store
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .migration_runs()
        .create(
            &env,
            NewMigrationRun {
                kind: MigrationKind::BulkImport,
                source_total: clean_total,
                backfill_expected: 0,
                subject_ref: None,
            },
            1_000_000,
        )
        .await
        .expect("create run3");
    for state in [MigrationState::Validating, MigrationState::Running] {
        store
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .migration_runs()
            .transition(&env, &run3, state)
            .await
            .expect("transition");
    }
    let clean_report = import_into_run(&ctx(&db, &env, scope), &run3, clean)
        .await
        .expect("import into run3");
    assert_eq!(clean_report.records.skipped, 3, "{clean_report:?}");
    assert_eq!(clean_report.records.failed, 0, "{clean_report:?}");
    store
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .migration_runs()
        .transition(&env, &run3, MigrationState::Reconciling)
        .await
        .expect("-> reconciling");
    let completed = store
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .migration_runs()
        .try_complete(&env, &run3)
        .await
        .expect("try_complete");
    assert_eq!(
        completed,
        CompletionOutcome::Completed,
        "a clean run still completes: the gates above are not refusing everything"
    );
}

/// KILLING a bulk import mid-stream and RESUMING it neither duplicates nor loses a
/// record (issue #55's last acceptance criterion).
///
/// # Why this is a real kill and not a smaller import
///
/// The first pass is CANCELLED, not truncated. The line source parks forever
/// ([`std::future::pending`]) on record [`KILL_AT`] after setting a flag; `tokio::select!`
/// sees the flag through [`WhenSet`] and DROPS the import future at that await point.
/// Nothing unwinds, no cleanup runs, no report is returned: the future simply stops
/// existing, which is what a killed process does to the work in flight. Everything the
/// import had already COMMITTED (the users, and every ledger batch already flushed)
/// survives, because those are committed transactions and not future state.
///
/// The cancellation point is deterministic (the source decides it), so this test cannot
/// pass by accident with a kill that landed at 0 or at the end. It asserts the strict
/// interval explicitly.
///
/// # What it then proves
///
/// The resume re-presents the WHOLE source, including every record the first pass already
/// imported, which is the honest worst case: a resumed operator generally cannot know
/// where the kill landed. After it:
///
/// * the population is EXACTLY the source set, once each (no duplicate, no loss);
/// * the run's ledger accounts EXACTLY `source_total` records, not one more (this is the
///   assertion that fails when a created record is keyed on the minted `usr_` id instead
///   of the record key: the resumed pass then reports the same source record as `skipped`
///   under a different blind index and the ledger double counts);
/// * and the run therefore COMPLETES through the same invariant-gated path an
///   uninterrupted import takes.
///
/// [`KILL_AT`]: a local constant
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn a_killed_import_resumes_without_duplicating_or_losing_records() {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll};

    /// The source set. Larger than the adapter's ingest batch, so the kill lands AFTER
    /// at least one ledger flush and the resume genuinely re-presents already-accounted
    /// records to the ingest's conflict clause.
    const TOTAL: usize = 700;
    /// Where the first pass is cancelled. Chosen past the 256-record ingest batch so
    /// some records are durable in the ledger and some are durable ONLY as users.
    const KILL_AT: usize = 400;

    /// A future that completes as soon as the shared flag is set, so `select!` can drop
    /// the import at a point the LINE SOURCE chooses rather than at a timeout.
    struct WhenSet(Arc<AtomicBool>);
    impl Future for WhenSet {
        type Output = ();
        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.0.load(Ordering::SeqCst) {
                Poll::Ready(())
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    /// A line source that yields the first `kill_at` records and then PARKS FOREVER,
    /// having flipped `reached` so the test can drop the import at exactly that point.
    struct KilledSource {
        lines: Vec<String>,
        cursor: usize,
        kill_at: usize,
        reached: Arc<AtomicBool>,
    }
    impl ironauth_import::LineSource for KilledSource {
        async fn next_line(&mut self) -> Option<Vec<u8>> {
            if self.cursor == self.kill_at {
                self.reached.store(true, Ordering::SeqCst);
                std::future::pending::<()>().await;
            }
            let line = self.lines[self.cursor].clone();
            self.cursor += 1;
            Some(line.into_bytes())
        }
    }

    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x55);
    let scope = db.seed_scope(&env).await;
    let store = db.store();
    let source: Vec<String> = (0..TOTAL)
        .map(|n| format!(r#"{{"identifier":"resume-{n}@example.test"}}"#))
        .collect();
    let source_total = i64::try_from(TOTAL).expect("source total fits");

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
                subject_ref: Some("import:resume"),
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

    // ---- pass 1: killed at KILL_AT -----------------------------------------------
    let context = ctx(&db, &env, scope);
    let reached = Arc::new(AtomicBool::new(false));
    {
        // The source announces the kill point and then parks forever. `select!` drops
        // the import future there, so it never observes another line and never returns.
        let killed = ironauth_import::import_lines_into_run(
            &context,
            &run,
            KilledSource {
                lines: source.clone(),
                cursor: 0,
                kill_at: KILL_AT,
                reached: Arc::clone(&reached),
            },
        );
        tokio::select! {
            _ = killed => panic!("the import must not run to completion: it was killed"),
            () = WhenSet(Arc::clone(&reached)) => {}
        }
    }
    assert!(
        reached.load(Ordering::SeqCst),
        "the source reached the kill point"
    );

    let after_kill = count_users(&db, scope).await;
    assert!(
        after_kill > 0 && after_kill < TOTAL,
        "the kill must land strictly inside the import: {after_kill} of {TOTAL} users"
    );
    assert_eq!(
        after_kill, KILL_AT,
        "the kill lands where the source put it, so the interruption is not timing dependent"
    );
    let ledger_after_kill = store
        .scoped(scope)
        .migration_runs()
        .tallies(&run)
        .await
        .expect("tallies");
    assert!(
        ledger_after_kill.accounted > 0,
        "at least one ledger batch flushed before the kill: {ledger_after_kill:?}"
    );
    assert!(
        ledger_after_kill.accounted < i64::try_from(after_kill).expect("fits"),
        "the ledger lags the creates by less than one batch, so some users are durable \
         with no ledger row and the resume must re-account them: {ledger_after_kill:?} \
         against {after_kill} users"
    );

    // ---- pass 2: resume by re-presenting the WHOLE source -------------------------
    let resumed = import_into_run(&context, &run, source.clone())
        .await
        .expect("resume the killed import");
    assert_eq!(resumed.records.processed, TOTAL as u64);
    assert_eq!(
        resumed.records.succeeded + resumed.records.skipped,
        TOTAL as u64,
        "every source record is either newly created or an idempotent skip: {resumed:?}"
    );
    assert_eq!(
        resumed.records.failed, 0,
        "a resume introduces no failures: {resumed:?}"
    );
    // The ledger halves say WHERE the first pass got to, which is the distinction the
    // ingest used to throw away: the resume wrote only the rows pass 1 had not, and
    // deduped exactly the ones it had.
    assert_eq!(
        resumed.ledger_written + resumed.ledger_deduped,
        TOTAL as u64,
        "every presented outcome was either written or deduped: {resumed:?}"
    );
    assert_eq!(
        resumed.ledger_deduped,
        u64::try_from(ledger_after_kill.accounted).expect("fits"),
        "the resume deduped exactly what the killed pass had already accounted: {resumed:?}"
    );

    // No LOSS: every source identifier exists.
    let population = count_users(&db, scope).await;
    assert_eq!(
        population, TOTAL,
        "the resumed population is exactly the source set"
    );
    // No DUPLICATE: the scope holds exactly one row per source identifier. `count_users`
    // above already equals TOTAL, so a duplicate would have to have displaced a distinct
    // record; this pins it directly against the database.
    let distinct: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT identifier_bidx) FROM users \
         WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("count distinct identifiers");
    assert_eq!(
        distinct, source_total,
        "one row per source identifier: no record was imported twice"
    );

    // The LEDGER accounts each source record exactly once, however many passes presented
    // it. Without the record-key subject this is TOTAL + (whatever the first pass had
    // flushed) and the run can never complete.
    let tallies = store
        .scoped(scope)
        .migration_runs()
        .tallies(&run)
        .await
        .expect("tallies");
    assert_eq!(
        tallies.accounted, source_total,
        "the resumed ledger accounts each source record exactly once: {tallies:?}"
    );

    // And the run therefore completes through the ordinary invariant gate.
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
    assert_eq!(
        outcome,
        CompletionOutcome::Completed,
        "a killed-then-resumed import completes exactly like an uninterrupted one"
    );
}

/// Create a run declaring `source_total` and drive it to `running`.
async fn running_run(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    source_total: i64,
) -> ironauth_store::MigrationRunId {
    let store = db.store();
    let run = store
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .migration_runs()
        .create(
            env,
            NewMigrationRun {
                kind: MigrationKind::BulkImport,
                source_total,
                backfill_expected: 0,
                subject_ref: None,
            },
            1_000_000,
        )
        .await
        .expect("create run");
    for state in [MigrationState::Validating, MigrationState::Running] {
        store
            .scoped(scope)
            .acting(db.test_actor(env), CorrelationId::generate(env))
            .migration_runs()
            .transition(env, &run, state)
            .await
            .expect("transition");
    }
    run
}

/// TWO unparseable lines are TWO accounted ledger rows, so a run carrying them can still
/// reconcile its COUNT (issue #55).
///
/// The defect this pins is a ledger one and is invisible at the engine's own report. Every
/// parse failure was keyed on one constant subject, the ingest dedups on the subject, and
/// so the second and every later bad line was silently DISCARDED by the `ON CONFLICT DO
/// NOTHING`. MEASURED with two bad lines and one good against a declared `source_total` of
/// 3: `imported=1 failed=1 accounted=2 remainder=1`, short forever, with no route on this
/// plane that could ever correct it. It also refuted the engine's own documented "nothing
/// is silently dropped".
#[tokio::test]
async fn two_unparseable_lines_are_two_accounted_ledger_rows() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x1a);
    let scope = db.seed_scope(&env).await;
    let store = db.store();

    let lines = vec![
        "{ this is not json".to_string(),
        "{ this is also not json, but different".to_string(),
        record_line("good@example.test", &argon2_hash("pw")),
    ];
    let source_total = i64::try_from(lines.len()).expect("fits");
    let run = running_run(&db, &env, scope, source_total).await;
    let report = import_into_run(&ctx(&db, &env, scope), &run, lines)
        .await
        .expect("import");
    assert_eq!(report.records.failed, 2, "{report:?}");
    assert_eq!(report.records.succeeded, 1, "{report:?}");
    // Three presented outcomes, three rows WRITTEN: nothing was absorbed by the conflict
    // clause. This is the exact quantity the constant key destroyed.
    assert_eq!(report.ledger_written, 3, "{report:?}");
    assert_eq!(report.ledger_deduped, 0, "{report:?}");

    let tallies = store
        .scoped(scope)
        .migration_runs()
        .tallies(&run)
        .await
        .expect("tallies");
    assert_eq!(
        tallies.accounted, source_total,
        "every source line is accounted, so the COUNT invariant reconciles: {tallies:?}"
    );
    assert_eq!(tallies.failed, 2, "{tallies:?}");

    // Both failures are READABLE, with distinct subjects and their own reasons.
    let offenders = store
        .scoped(scope)
        .migration_runs()
        .list_violations(&run, InvariantKind::Consistency, 10, None)
        .await
        .expect("violations");
    assert_eq!(offenders.len(), 2, "{offenders:?}");
    assert_ne!(
        offenders[0].subject, offenders[1].subject,
        "two bad lines are two subjects: {offenders:?}"
    );

    // And re-presenting the SAME bad lines adds no third and fourth row: the key is a
    // function of the line, so a resume dedups it exactly like a good record.
    let again = vec![
        "{ this is not json".to_string(),
        "{ this is also not json, but different".to_string(),
    ];
    let resumed = import_into_run(&ctx(&db, &env, scope), &run, again)
        .await
        .expect("re-present");
    assert_eq!(resumed.ledger_written, 0, "{resumed:?}");
    assert_eq!(resumed.ledger_deduped, 2, "{resumed:?}");
    let after = store
        .scoped(scope)
        .migration_runs()
        .tallies(&run)
        .await
        .expect("tallies");
    assert_eq!(after.accounted, source_total, "{after:?}");
}

/// A source EDITED between two attempts still reconciles (issue #55).
///
/// The ledger key has to be a property of the record that cannot appear or disappear, and
/// "the id, else the external id, else the login handle" is not one: the documented
/// recovery procedure is to post the source again, and an operator does that from whatever
/// export they have now. MEASURED on the old key: pass 1 delivers a record with no external
/// id, pass 2 re-presents the same identity now carrying one, `accounted` reaches 3 against
/// a `source_total` of 2, `remainder == -1`, and the run is stuck in `reconciling` with an
/// invariant that can never be satisfied again. The POPULATION was correct throughout,
/// which is what makes the defect so quiet.
#[tokio::test]
async fn a_source_edited_between_attempts_still_reconciles() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x1b);
    let scope = db.seed_scope(&env).await;
    let store = db.store();

    let run = running_run(&db, &env, scope, 2).await;

    // Pass 1: two records, the first carrying NO external id.
    let pass1 = vec![
        r#"{"identifier":"drift@example.test"}"#.to_string(),
        r#"{"identifier":"steady@example.test"}"#.to_string(),
    ];
    let first = import_into_run(&ctx(&db, &env, scope), &run, pass1)
        .await
        .expect("pass 1");
    assert_eq!(first.records.succeeded, 2, "{first:?}");
    assert_eq!(first.ledger_written, 2, "{first:?}");

    // Pass 2: the SAME two identities, but the first now carries an external id, exactly
    // as a corrected export would.
    let pass2 = vec![
        r#"{"identifier":"drift@example.test","external_id":"crm-77"}"#.to_string(),
        r#"{"identifier":"steady@example.test"}"#.to_string(),
    ];
    let second = import_into_run(&ctx(&db, &env, scope), &run, pass2)
        .await
        .expect("pass 2");
    assert_eq!(
        second.records.skipped, 2,
        "both identities already exist: {second:?}"
    );
    assert_eq!(
        second.ledger_written, 0,
        "the edited record is the SAME ledger subject, so it writes no second row: \
         {second:?}"
    );
    assert_eq!(second.ledger_deduped, 2, "{second:?}");

    let tallies = store
        .scoped(scope)
        .migration_runs()
        .tallies(&run)
        .await
        .expect("tallies");
    assert_eq!(
        tallies.accounted, 2,
        "two source records, two accounted rows, however the source was edited: {tallies:?}"
    );
    assert_eq!(count_users(&db, scope).await, 2);

    // And the run COMPLETES, which under the old key it could never do again.
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
    assert_eq!(outcome, CompletionOutcome::Completed, "{outcome:?}");
}

/// A source carrying TWO records under ONE login handle wedges its run, and the report
/// SAYS SO (issue #55).
///
/// This is the residue the handle key does not remove and cannot: two records with one
/// handle are one ledger subject by construction, so they account one row against a
/// declared two and the count invariant is unsatisfiable. What the engine owes an operator
/// in that case is the difference between "the ledger took this record" and "the ledger
/// already had this subject", which is `ledger_deduped`. On a FIRST pass over a fresh run
/// there is nothing else to dedup against, so a non-zero value there is a duplicate key IN
/// THE SOURCE and nothing else. Before this, a caller could not tell that from a truncated
/// upload.
#[tokio::test]
async fn two_records_sharing_a_login_handle_wedge_the_run_and_the_report_says_so() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x1c);
    let scope = db.seed_scope(&env).await;
    let store = db.store();

    let run = running_run(&db, &env, scope, 2).await;
    let lines = vec![
        r#"{"identifier":"twin@example.test","external_id":"crm-1"}"#.to_string(),
        r#"{"identifier":"twin@example.test","external_id":"crm-2"}"#.to_string(),
    ];
    let report = import_into_run(&ctx(&db, &env, scope), &run, lines)
        .await
        .expect("import");
    assert_eq!(report.records.processed, 2, "{report:?}");
    assert_eq!(report.records.succeeded, 1, "{report:?}");
    assert_eq!(
        report.records.skipped, 1,
        "the scope's unique constraint refuses the second: {report:?}"
    );
    assert_eq!(
        report.ledger_written, 1,
        "one subject, one ledger row: {report:?}"
    );
    assert_eq!(
        report.ledger_deduped, 1,
        "and the pass REPORTS the row it could not write, which is the whole signal: \
         {report:?}"
    );

    // The run is genuinely wedged: one accounted against a declared two, and no amount of
    // re-presenting the source changes it.
    let again = import_into_run(
        &ctx(&db, &env, scope),
        &run,
        vec![
            r#"{"identifier":"twin@example.test","external_id":"crm-1"}"#.to_string(),
            r#"{"identifier":"twin@example.test","external_id":"crm-2"}"#.to_string(),
        ],
    )
    .await
    .expect("re-present");
    assert_eq!(again.ledger_written, 0, "{again:?}");
    let tallies = store
        .scoped(scope)
        .migration_runs()
        .tallies(&run)
        .await
        .expect("tallies");
    assert_eq!(tallies.accounted, 1, "{tallies:?}");

    store
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .migration_runs()
        .transition(&env, &run, MigrationState::Reconciling)
        .await
        .expect("-> reconciling");
    let blocked = store
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .migration_runs()
        .try_complete(&env, &run)
        .await
        .expect("try_complete");
    let CompletionOutcome::Blocked(violated) = blocked else {
        panic!("a run one record short must not complete: {blocked:?}");
    };
    assert!(
        violated
            .iter()
            .any(|eval| eval.kind == InvariantKind::Count),
        "{violated:?}"
    );

    // The ONLY exit is the audited abandonment, because nothing may rewrite the declared
    // ground truth or delete a ledger row.
    store
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .migration_runs()
        .abandon(
            &env,
            &run,
            "source carried two records for one login handle",
            None,
        )
        .await
        .expect("abandon");
    let closed = store
        .scoped(scope)
        .migration_runs()
        .get(&run)
        .await
        .expect("get");
    assert_eq!(closed.state, MigrationState::Abandoned);
    assert_eq!(
        closed.abandoned_reason.as_deref(),
        Some("source carried two records for one login handle")
    );
}

/// An import record carrying one ACTIVE TOTP enrollment for `identifier`.
fn totp_record_line(
    identifier: &str,
    seed_base32: &str,
    last_consumed_step: Option<i64>,
) -> String {
    let consumed = match last_consumed_step {
        Some(step) => step.to_string(),
        None => "null".to_owned(),
    };
    format!(
        r#"{{"identifier":"{identifier}","password_hash":"{}","totp":[{{"seed_base32":"{seed_base32}","algorithm":"SHA1","digits":6,"period_secs":30,"friendly_name":"Authenticator","status":"active","last_consumed_step":{consumed}}}]}}"#,
        argon2_hash("pw")
    )
}

#[tokio::test]
async fn an_imported_totp_enrollment_verifies_against_the_original_authenticator() {
    // Issue #55 asks that imported TOTP enrollments WORK for MFA after import, and the write
    // path alone cannot show that. `restore_totp` re-seals the seed under the DESTINATION
    // environment's DEK and re-mints the row's id, subject and key version, so the enrollment
    // can be written, listed and reported healthy while the seed it restored is not the one the
    // user's authenticator holds. Every symptom of that lands on the END USER at their next
    // sign-in, which is the worst place to discover it and the reason this asserts on a CODE
    // rather than on the row.
    //
    // A TOTP seed is a portable shared secret, unlike a passkey, which is exactly why the
    // export carries it and why this round trip has to hold.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x7a);
    let scope = db.seed_scope(&env).await;

    // The seed the user's authenticator app holds. Base32 is the form the export emits.
    let seed_bytes: Vec<u8> = b"imported-totp-seed".to_vec();
    let seed_base32 = ironauth_jose::base32_encode(&seed_bytes);

    let (report, outcomes) = run_import(
        &db,
        &env,
        scope,
        vec![totp_record_line("totp@x.test", &seed_base32, Some(41))],
    )
    .await;
    assert_eq!(report.succeeded, 1, "the record imported: {outcomes:?}");

    let user = db
        .store()
        .scoped(scope)
        .users()
        .list(UserListFilter::default(), 10, None)
        .await
        .expect("list users")
        .into_iter()
        .next()
        .expect("the imported user");

    let material = db
        .store()
        .scoped(scope)
        .totp_credentials()
        .open_active_material(&user.id)
        .await
        .expect("open the restored factor")
        .expect("the import restored an ACTIVE factor, so one is resolvable");

    // The parameters must survive, because a code is a function of all of them: a factor
    // restored at the wrong period or digit count produces a well-formed code that never
    // matches, which reads to an operator exactly like a user typing it wrong.
    assert_eq!(material.algorithm, "SHA1");
    assert_eq!(material.digits, 6);
    assert_eq!(material.period_secs, 30);
    assert_eq!(material.status, "active");

    // THE PROPERTY. A code computed from the ORIGINAL seed, as the user's authenticator would
    // compute it, must equal the code computed from what the destination actually stored.
    let params = ironauth_jose::TotpParams::authenticator_default();
    let at_step = 60 * 60;
    assert_eq!(
        ironauth_jose::code_at(&material.seed, params, at_step),
        ironauth_jose::code_at(&seed_bytes, params, at_step),
        "the restored seed does not agree with the authenticator's: the enrollment survived \
         import as a ROW but not as a working factor, so every imported user would be locked \
         out of a second factor they can still see listed"
    );

    // The single-use step comes across too. Without it a replay of the last code the user
    // entered before the migration is accepted once more on the destination, which is the one
    // guarantee a TOTP step counter exists to give.
    assert_eq!(
        material.last_consumed_step,
        Some(41),
        "the consumed step was not restored, so the last pre-migration code is replayable"
    );
}

/// Issue #55 criterion 4: an out-of-bounds cost is rejected with a PER-RECORD error
/// naming that record, for every scheme that has a bound, and the good records around
/// it still import.
///
/// `a_bad_record_does_not_abort_the_batch` already drives one over-cost bcrypt record,
/// but it asserts COUNTS and throws the outcomes away. A count says two records failed;
/// it does not say which, or why, and an engine that attributed every failure to the
/// same key or reported an empty reason would satisfy it. The criterion is about the
/// per-record report, so this reads the report.
///
/// One record per bounded parameter, rather than one representative. The bounds are
/// enforced by a different arm of `ForeignHash::parse` per scheme, and a sweep over one
/// scheme says nothing about the arms it did not enter.
#[tokio::test]
async fn every_out_of_bounds_cost_is_a_per_record_failure_naming_that_record() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x71);
    let scope = db.seed_scope(&env).await;

    // Each entry is (login handle, a hash whose cost is one step outside the bound).
    let over_bounds = [
        ("bcrypt-dos@x.test", format!("$2b$31${}", "a".repeat(53))),
        (
            "scrypt-dos@x.test",
            "$scrypt$ln=21,r=8,p=1$c2FsdHNhbHQ$aGFzaGhhc2g".to_owned(),
        ),
        (
            "pbkdf2-dos@x.test",
            "$pbkdf2-sha256$i=10000001$c2FsdHNhbHQ$aGFzaGhhc2g".to_owned(),
        ),
        (
            "argon2-dos@x.test",
            "$argon2id$v=19$m=4194305,t=2,p=1$c29tZXNhbHQ$aGFzaGhhc2hoYXNo".to_owned(),
        ),
        (
            "shacrypt-dos@x.test",
            "$6$rounds=1000001$saltstring$x".to_owned(),
        ),
    ];

    let mut lines = vec![record_line("before@x.test", &bcrypt_hash("pw"))];
    for (identifier, hash) in &over_bounds {
        lines.push(record_line(identifier, hash));
    }
    lines.push(record_line("after@x.test", &bcrypt_hash("pw")));

    let (report, outcomes) = run_import(&db, &env, scope, lines).await;

    let expected_failures = over_bounds.len() as u64;
    assert_eq!(report.processed, expected_failures + 2);
    assert_eq!(
        report.failed, expected_failures,
        "every out-of-bounds record must fail, and only those: {outcomes:?}"
    );
    assert_eq!(
        report.succeeded, 2,
        "the good records on either side of the failures still import"
    );

    // The attribution: one failure per bad record, keyed to THAT record.
    let failures: Vec<(String, String)> = outcomes
        .iter()
        .filter_map(|outcome| match outcome {
            RecordOutcome::Failed(error) => Some((error.key.clone(), error.reason.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(failures.len() as u64, expected_failures, "{outcomes:?}");
    for (identifier, _) in &over_bounds {
        let found = failures
            .iter()
            .find(|(key, _)| key == identifier)
            .unwrap_or_else(|| {
                panic!("no failure was reported against {identifier}: {failures:?}")
            });
        assert!(
            !found.1.trim().is_empty(),
            "{identifier} failed with an EMPTY reason, so the report says a record was \
             dropped and nothing about why: {failures:?}"
        );
    }

    // Nothing was silently dropped: the two good records are the two users, and the
    // rejected ones left no partial row behind.
    assert_eq!(count_users(&db, scope).await, 2);
}
