// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reset schema, issuance and atomic credential completion against isolated Postgres.
//! Schema rows are metadata fixtures; repository cases use actual signup and
//! mailbox verification, and change only their own isolated fixture credentials.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{PasswordResetChallengeId, RecipientChallengeId, Scope};
use sqlx::Row;

async fn insert_fixture(
    db: &TestDatabase,
    scope: Scope,
    id: &PasswordResetChallengeId,
    bound: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO password_reset_challenges \
         (id,tenant_id,environment_id,client_id,browser_binding_hash,authorization_return_to,\
          subject,identifier_id,recipient_revision,recovery_id,credential_digest,code_hash,created_at,expires_at,cancellation_token_digest) \
         VALUES ($1,$2,$3,'fixture-client',decode(repeat('ab',32),'hex'),'/authorize?fixture=1',\
          $4,$5,$6,$7,$8,'fixture-hash',TIMESTAMPTZ '2026-10-03 00:00:00Z',\
          TIMESTAMPTZ '2026-10-03 00:05:00Z',$9)",
    )
    .bind(id.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(bound.then_some("fixture-subject"))
    .bind(bound.then_some("fixture-identifier"))
    .bind(bound.then_some("fixture-revision"))
    .bind(bound.then_some("fixture-recovery"))
    .bind(bound.then_some(vec![1_u8; 32]))
    .bind(bound.then(|| { use sha2::{Digest, Sha256}; Sha256::digest(id.to_string()).to_vec() }))
    .execute(db.owner_pool())
    .await?;
    Ok(())
}

fn sqlstate(error: &sqlx::Error) -> Option<String> {
    error
        .as_database_error()?
        .code()
        .map(std::borrow::Cow::into_owned)
}

#[tokio::test]
async fn reset_schema_forces_scope_and_refuses_authority_rewrites() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let other = db.seed_scope(&env).await;
    let id = PasswordResetChallengeId::generate(&env, &scope);
    insert_fixture(&db, scope, &id, true).await.unwrap();
    let flags = sqlx::query("SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE relname='password_reset_challenges'")
        .fetch_one(db.owner_pool()).await.unwrap();
    assert!(flags.get::<bool, _>("relrowsecurity"));
    assert!(flags.get::<bool, _>("relforcerowsecurity"));
    let mut tx = db.app_pool().begin().await.unwrap();
    sqlx::query("SELECT set_config('ironauth.tenant_id',$1,true),set_config('ironauth.environment_id',$2,true)")
        .bind(other.tenant().to_string()).bind(other.environment().to_string()).execute(&mut *tx).await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM password_reset_challenges")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(count, 0);
    for query in [
        "DELETE FROM password_reset_challenges WHERE id=$1",
        "UPDATE password_reset_challenges SET attempt_count=1 WHERE id=$1",
    ] {
        assert_eq!(
            sqlx::query(query)
                .bind(id.to_string())
                .execute(&mut *tx)
                .await
                .unwrap()
                .rows_affected(),
            0
        );
    }
    tx.commit().await.unwrap();

    let mut tx = db.app_pool().begin().await.unwrap();
    sqlx::query("SELECT set_config('ironauth.tenant_id',$1,true),set_config('ironauth.environment_id',$2,true)")
        .bind(other.tenant().to_string()).bind(other.environment().to_string()).execute(&mut *tx).await.unwrap();
    let forged = PasswordResetChallengeId::generate(&env, &scope);
    let error = sqlx::query("INSERT INTO password_reset_challenges (id,tenant_id,environment_id,client_id,browser_binding_hash,authorization_return_to,code_hash,created_at,expires_at) VALUES ($1,$2,$3,'fixture-client',decode(repeat('ab',32),'hex'),'/authorize?fixture=1','fixture-hash',TIMESTAMPTZ '2026-10-03 00:00:00Z',TIMESTAMPTZ '2026-10-03 00:05:00Z')")
        .bind(forged.to_string()).bind(scope.tenant().to_string()).bind(scope.environment().to_string())
        .execute(&mut *tx).await.expect_err("WITH CHECK rejects foreign insertion");
    assert_eq!(sqlstate(&error).as_deref(), Some("42501"));
    tx.rollback().await.unwrap();
    for column in [
        "subject",
        "identifier_id",
        "recipient_revision",
        "recovery_id",
        "credential_digest",
        "cancellation_token_digest",
        "browser_binding_hash",
        "authorization_return_to",
        "client_id",
        "code_hash",
        "expires_at",
        "tenant_id",
        "environment_id",
    ] {
        let error = sqlx::query(&format!(
            "UPDATE password_reset_challenges SET {column}={column}"
        ))
        .execute(db.app_pool())
        .await
        .expect_err("runtime cannot rewrite bound authority");
        assert_eq!(sqlstate(&error).as_deref(), Some("42501"), "{column}");
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM password_reset_challenges WHERE id=$1 AND attempt_count=0",
    )
    .bind(id.to_string())
    .fetch_one(db.owner_pool())
    .await
    .unwrap();
    assert_eq!(
        count, 1,
        "foreign and unprivileged writes left the record intact"
    );
    assert!(PasswordResetChallengeId::parse_in_scope(&id.to_string(), &other).is_err());
    assert!(RecipientChallengeId::parse_in_scope(&id.to_string(), &scope).is_err());
    assert!(!format!("{id:?}").contains(&id.to_string()));
}

#[tokio::test]
async fn reset_schema_rejects_partial_completion_and_unbounded_attempts() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let id = PasswordResetChallengeId::generate(&env, &scope);
    insert_fixture(&db, scope, &id, true).await.unwrap();
    for change in [
        "attempt_count=6",
        "delivery_state='accepted'",
        "delivery_state='accepted',delivery_finished_at=created_at,notified_channels=0",
        "delivery_state='pending',notified_channels=1",
        "delivery_state='uncertain',delivery_finished_at=created_at-interval '1 second'",
        "state='completed',attempt_count=1,finished_at=created_at+interval '1 minute',completion_request_hash=decode(repeat('ab',32),'hex'),completion_credential_digest=decode(repeat('cd',32),'hex')",
        "attempt_count=-1",
        "expires_at=created_at",
        "expires_at=created_at+interval '11 minutes'",
        "browser_binding_hash=decode('ab','hex')",
        "identifier_id=NULL",
        "cancellation_token_digest=NULL",
        "cancellation_token_digest=decode('ab','hex')",
        "state='completed'",
        "finished_at=created_at+interval '1 minute'",
        "state='completed',attempt_count=1,finished_at=created_at+interval '1 minute',completion_request_hash=decode(repeat('ab',32),'hex')",
        "state='completed',attempt_count=1,finished_at=expires_at,completion_request_hash=decode(repeat('ab',32),'hex'),completion_credential_digest=decode(repeat('cd',32),'hex')",
    ] {
        let error = sqlx::query(&format!(
            "UPDATE password_reset_challenges SET {change} WHERE id=$1"
        ))
        .bind(id.to_string())
        .execute(db.owner_pool())
        .await
        .expect_err("invalid state refused");
        assert_eq!(sqlstate(&error).as_deref(), Some("23514"), "{change}");
    }
    let next = PasswordResetChallengeId::generate(&env, &scope);
    let error = insert_fixture(&db, scope, &next, true)
        .await
        .expect_err("one pending reset per subject");
    assert_eq!(sqlstate(&error).as_deref(), Some("23505"));
    sqlx::query("UPDATE password_reset_challenges SET state='cancelled',finished_at=created_at+interval '1 minute' WHERE id=$1")
        .bind(id.to_string()).execute(db.owner_pool()).await.unwrap();
    insert_fixture(&db, scope, &next, true).await.unwrap();
    let decoy = PasswordResetChallengeId::generate(&env, &scope);
    insert_fixture(&db, scope, &decoy, false).await.unwrap();
    let error = sqlx::query("UPDATE password_reset_challenges SET delivery_state='accepted',notified_channels=1,delivery_finished_at=created_at,state='completed',attempt_count=1,finished_at=created_at+interval '1 minute',completion_request_hash=decode(repeat('ab',32),'hex'),completion_credential_digest=decode(repeat('cd',32),'hex') WHERE id=$1")
        .bind(decoy.to_string()).execute(db.owner_pool()).await.expect_err("decoy cannot become completed authority");
    assert_eq!(sqlstate(&error).as_deref(), Some("23514"));
    sqlx::query("UPDATE password_reset_challenges SET delivery_state='accepted',notified_channels=1,delivery_finished_at=created_at,state='completed',attempt_count=1,finished_at=created_at+interval '1 minute',completion_request_hash=decode(repeat('ab',32),'hex'),completion_credential_digest=decode(repeat('cd',32),'hex') WHERE id=$1")
        .bind(next.to_string()).execute(db.owner_pool()).await.expect("complete metadata shape is representable; this is not a credential mutation");
}

const HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaGhhc2hoYXNo";
const EMAIL: &str = "Reset.Owner@example.test";

fn now_micros(env: &Env) -> i64 {
    i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap()
}

async fn verify_reset_mailbox(db: &TestDatabase, env: &Env, subject: &ironauth_store::UserId) {
    use ironauth_store::{CorrelationId, NewRecipientChallenge, RecipientAttempt};
    let scope = subject.scope();
    let store = db.store();
    let acting = store
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env));
    let id = RecipientChallengeId::generate(env, &scope);
    acting
        .recipient_verification()
        .start(
            env,
            NewRecipientChallenge {
                id: &id,
                subject,
                email: EMAIL,
                code_hash: HASH,
                expires_at_unix_micros: now_micros(env) + 300_000_000,
            },
        )
        .await
        .unwrap();
    let challenge = store
        .scoped(scope)
        .recipient_verification()
        .challenge(env, subject, &id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        acting
            .recipient_verification()
            .attempt(env, subject, &challenge, true)
            .await
            .unwrap(),
        RecipientAttempt::Verified
    );
}

async fn verified_account(db: &TestDatabase, env: &Env, scope: Scope) -> ironauth_store::UserId {
    use ironauth_store::CorrelationId;
    let subject = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .users()
        .register(env, EMAIL, HASH, None)
        .await
        .unwrap();
    verify_reset_mailbox(db, env, &subject).await;
    subject
}

async fn recovery_case(
    db: &TestDatabase,
    env: &Env,
    subject: &ironauth_store::UserId,
) -> ironauth_store::RecoveryFlowId {
    use ironauth_store::{
        CorrelationId, NewRecoveryFlow, RecoveryEntryPoint, RecoveryFlowId, RecoveryMethod,
    };
    let id = RecoveryFlowId::generate(env, &subject.scope());
    db.store()
        .scoped(subject.scope())
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .recovery_flows()
        .initiate(
            env,
            NewRecoveryFlow {
                id: &id,
                subject,
                entry_point: RecoveryEntryPoint::LostPassword,
                recover_acr: "urn:ironauth:acr:pwd",
                cancel_token_digest: &[7; 32],
                recipient: EMAIL,
                hold_until_unix_micros: None,
                method: RecoveryMethod::Standard,
            },
            0,
        )
        .await
        .unwrap()
}

async fn start_reset(
    db: &TestDatabase,
    env: &Env,
    id: &PasswordResetChallengeId,
    account: Option<ironauth_store::PasswordResetAccount<'_>>,
) -> Result<Option<String>, ironauth_store::StoreError> {
    use ironauth_store::{ClientId, CorrelationId, NewPasswordReset};
    use sha2::{Digest, Sha256};
    // Deterministic test digest only. Production must hash a secret cancellation token.
    let cancellation_digest: [u8; 32] = Sha256::digest(id.to_string()).into();
    let cancellation_token_digest = account.as_ref().map(|_| &cancellation_digest);
    db.store()
        .scoped(id.scope())
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .password_reset()
        .start(
            env,
            NewPasswordReset {
                id,
                client: &ClientId::generate(env, &id.scope()),
                browser_binding_hash: &[3; 32],
                authorization_return_to: "/authorize?client_id=fixture",
                account,
                cancellation_token_digest,
                code_hash: HASH,
                expires_at_unix_micros: now_micros(env) + 300_000_000,
            },
        )
        .await
}

#[tokio::test]
async fn reset_issuance_derives_current_authority_and_enforces_browser_scope_and_cooldown() {
    use ironauth_store::{PasswordResetAccount, StoreError};
    use sha2::{Digest, Sha256};
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = verified_account(&db, &env, scope).await;
    let recovery = recovery_case(&db, &env, &subject).await;
    let id = PasswordResetChallengeId::generate(&env, &scope);
    assert_eq!(
        start_reset(
            &db,
            &env,
            &id,
            Some(PasswordResetAccount {
                subject: &subject,
                recovery: &recovery,
            })
        )
        .await
        .unwrap()
        .as_deref(),
        Some(EMAIL)
    );
    let row = sqlx::query("SELECT subject,identifier_id,recipient_revision,recovery_id,credential_digest,attempt_count FROM password_reset_challenges WHERE id=$1")
        .bind(id.to_string()).fetch_one(db.owner_pool()).await.unwrap();
    let verified = db
        .store()
        .scoped(scope)
        .recipient_verification()
        .current(&subject, EMAIL)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.get::<String, _>("subject"), subject.to_string());
    assert_eq!(
        row.get::<String, _>("identifier_id"),
        verified.identifier_id.to_string()
    );
    assert_eq!(
        row.get::<String, _>("recipient_revision"),
        verified.revision.to_string()
    );
    assert_eq!(row.get::<String, _>("recovery_id"), recovery.to_string());
    assert_eq!(
        row.get::<Vec<u8>, _>("credential_digest"),
        Sha256::digest(HASH.as_bytes()).to_vec()
    );
    assert_eq!(row.get::<i32, _>("attempt_count"), 0);
    let read = db.store().scoped(scope).password_reset();
    assert_eq!(
        read.challenge(&env, &id, &[3; 32])
            .await
            .unwrap()
            .unwrap()
            .code_hash,
        HASH
    );
    assert!(read.challenge(&env, &id, &[4; 32]).await.unwrap().is_none());
    let other = db.seed_scope(&env).await;
    assert!(
        db.store()
            .scoped(other)
            .password_reset()
            .challenge(&env, &id, &[3; 32])
            .await
            .unwrap()
            .is_none()
    );
    let next = PasswordResetChallengeId::generate(&env, &scope);
    assert!(matches!(
        start_reset(
            &db,
            &env,
            &next,
            Some(PasswordResetAccount {
                subject: &subject,
                recovery: &recovery,
            })
        )
        .await,
        Err(StoreError::QuotaExceeded)
    ));
    assert!(read.challenge(&env, &id, &[3; 32]).await.unwrap().is_some());
    let audit = db.store().scoped(scope).audit().list().await.unwrap();
    assert_eq!(
        audit
            .iter()
            .filter(|row| row.action == "password_reset.start")
            .count(),
        1
    );
}

#[tokio::test]
async fn reset_issuance_refuses_cancelled_or_foreign_cases_and_decoy_has_no_account_binding() {
    use ironauth_store::{CorrelationId, PasswordResetAccount, RecoveryCancelReason, StoreError};
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = verified_account(&db, &env, scope).await;
    let recovery = recovery_case(&db, &env, &subject).await;
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .recovery_flows()
        .cancel(&env, &recovery, RecoveryCancelReason::UserNotification)
        .await
        .unwrap();
    let id = PasswordResetChallengeId::generate(&env, &scope);
    assert!(matches!(
        start_reset(
            &db,
            &env,
            &id,
            Some(PasswordResetAccount {
                subject: &subject,
                recovery: &recovery,
            })
        )
        .await,
        Err(StoreError::NotFound)
    ));
    let other = db.seed_scope(&env).await;
    let foreign = PasswordResetChallengeId::generate(&env, &other);
    assert!(matches!(
        start_reset(
            &db,
            &env,
            &foreign,
            Some(PasswordResetAccount {
                subject: &subject,
                recovery: &recovery,
            })
        )
        .await,
        Err(StoreError::NotFound)
    ));
    assert!(start_reset(&db, &env, &id, None).await.unwrap().is_none());
    let row = sqlx::query("SELECT subject,credential_digest,recipient_revision FROM password_reset_challenges WHERE id=$1")
        .bind(id.to_string()).fetch_one(db.owner_pool()).await.unwrap();
    assert!(row.get::<Option<String>, _>("subject").is_none());
    assert!(row.get::<Option<Vec<u8>>, _>("credential_digest").is_none());
    assert!(row.get::<Option<String>, _>("recipient_revision").is_none());
    assert!(
        db.store()
            .scoped(scope)
            .password_reset()
            .challenge(&env, &id, &[3; 32])
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn reset_issuance_refuses_unverified_accounts_and_another_subjects_case() {
    use ironauth_store::{CorrelationId, PasswordResetAccount, StoreError};
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.store();
    let scoped = store.scoped(scope);
    let unverified = scoped
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .users()
        .register(&env, "unverified@example.test", HASH, None)
        .await
        .unwrap();
    let recovery = recovery_case(&db, &env, &unverified).await;
    let id = PasswordResetChallengeId::generate(&env, &scope);
    assert!(matches!(
        start_reset(
            &db,
            &env,
            &id,
            Some(PasswordResetAccount {
                subject: &unverified,
                recovery: &recovery,
            })
        )
        .await,
        Err(StoreError::NotFound)
    ));
    let verified = verified_account(&db, &env, scope).await;
    assert!(matches!(
        start_reset(
            &db,
            &env,
            &id,
            Some(PasswordResetAccount {
                subject: &verified,
                recovery: &recovery,
            })
        )
        .await,
        Err(StoreError::NotFound)
    ));
    assert!(
        scoped
            .password_reset()
            .challenge(&env, &id, &[3; 32])
            .await
            .unwrap()
            .is_none()
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM password_reset_challenges WHERE tenant_id=$1 AND environment_id=$2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .unwrap();
    assert_eq!(count, 0);
    assert!(
        !scoped
            .audit()
            .list()
            .await
            .unwrap()
            .iter()
            .any(|row| row.action == "password_reset.start")
    );
}

#[tokio::test]
async fn reset_reissue_cancels_prior_authority_and_reads_expire_at_the_deadline() {
    use ironauth_store::PasswordResetAccount;
    use std::time::{Duration, SystemTime};
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH + Duration::from_secs(1000), 1479);
    let scope = db.seed_scope(&env).await;
    let subject = verified_account(&db, &env, scope).await;
    let recovery = recovery_case(&db, &env, &subject).await;
    let first = PasswordResetChallengeId::generate(&env, &scope);
    start_reset(
        &db,
        &env,
        &first,
        Some(PasswordResetAccount {
            subject: &subject,
            recovery: &recovery,
        }),
    )
    .await
    .unwrap();
    clock.advance(Duration::from_secs(61));
    let second = PasswordResetChallengeId::generate(&env, &scope);
    start_reset(
        &db,
        &env,
        &second,
        Some(PasswordResetAccount {
            subject: &subject,
            recovery: &recovery,
        }),
    )
    .await
    .unwrap();
    let read = db.store().scoped(scope).password_reset();
    assert!(
        read.challenge(&env, &first, &[3; 32])
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        read.challenge(&env, &second, &[3; 32])
            .await
            .unwrap()
            .is_some()
    );
    let prior = sqlx::query("SELECT state,finished_at IS NOT NULL AS finished FROM password_reset_challenges WHERE id=$1")
        .bind(first.to_string()).fetch_one(db.owner_pool()).await.unwrap();
    assert_eq!(prior.get::<String, _>("state"), "cancelled");
    assert!(prior.get::<bool, _>("finished"));
    clock.advance(Duration::from_secs(300));
    assert!(
        read.challenge(&env, &second, &[3; 32])
            .await
            .unwrap()
            .is_none()
    );
}

const NEW_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$bmV3c2FsdG5ldw$bmV3aGFzaG5ldw";

async fn pending_reset_fixture(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
) -> (
    ironauth_store::UserId,
    ironauth_store::RecoveryFlowId,
    ironauth_store::PasswordResetChallenge,
) {
    let subject = verified_account(db, env, scope).await;
    let recovery = recovery_case(db, env, &subject).await;
    let id = PasswordResetChallengeId::generate(env, &scope);
    start_reset(
        db,
        env,
        &id,
        Some(ironauth_store::PasswordResetAccount {
            subject: &subject,
            recovery: &recovery,
        }),
    )
    .await
    .unwrap();
    let challenge = db
        .store()
        .scoped(scope)
        .password_reset()
        .challenge(env, &id, &[3; 32])
        .await
        .unwrap()
        .unwrap();
    (subject, recovery, challenge)
}

// Isolated store tests explicitly simulate adapter acceptance. Actual SMTP
// transport tests are separate; this helper is not evidence of delivered mail.
async fn reset_fixture(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
) -> (
    ironauth_store::UserId,
    ironauth_store::RecoveryFlowId,
    ironauth_store::PasswordResetChallenge,
) {
    let fixture = pending_reset_fixture(db, env, scope).await;
    record_reset_delivery(
        db,
        env,
        &fixture.2.id,
        ironauth_store::PasswordResetDelivery::Accepted,
        1,
    )
    .await
    .unwrap();
    fixture
}

async fn record_reset_delivery(
    db: &TestDatabase,
    env: &Env,
    id: &PasswordResetChallengeId,
    result: ironauth_store::PasswordResetDelivery,
    channels: u32,
) -> Result<(), ironauth_store::StoreError> {
    db.store()
        .scoped(id.scope())
        .acting(
            db.test_actor(env),
            ironauth_store::CorrelationId::generate(env),
        )
        .password_reset()
        .record_delivery(env, id, result, channels)
        .await
}

async fn complete_reset(
    db: &TestDatabase,
    env: &Env,
    challenge: &ironauth_store::PasswordResetChallenge,
    matched: bool,
    request: u8,
) -> Result<ironauth_store::PasswordResetOutcome, ironauth_store::StoreError> {
    use ironauth_store::{CompletePasswordReset, CorrelationId};
    db.store()
        .scoped(challenge.id.scope())
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .password_reset()
        .complete(
            env,
            CompletePasswordReset {
                challenge,
                browser_binding_hash: &[3; 32],
                code_matched: matched,
                new_password_hash: NEW_HASH,
                request_hash: &[request; 32],
            },
        )
        .await
}

async fn reset_session(
    db: &TestDatabase,
    env: &Env,
    subject: &ironauth_store::UserId,
) -> ironauth_store::SessionId {
    use ironauth_store::{CorrelationId, NewSession, SessionId};
    let id = SessionId::generate(env, &subject.scope());
    db.store()
        .scoped(subject.scope())
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .sessions()
        .rotate(
            env,
            &id,
            None,
            NewSession {
                impersonation: None,
                subject: &subject.to_string(),
                auth_methods: "pwd",
                auth_time_micros: 0,
                idle_expires_micros: 4_102_444_800_000_000,
                absolute_expires_micros: 4_102_444_800_000_000,
                user_agent: None,
                peer_ip: None,
            },
        )
        .await
        .unwrap();
    id
}

#[tokio::test]
async fn reset_completion_changes_password_revokes_session_and_replays_only_the_same_request() {
    use ironauth_store::{PasswordResetOutcome, RecoveryState};
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (subject, recovery, challenge) = reset_fixture(&db, &env, scope).await;
    let session = reset_session(&db, &env, &subject).await;
    assert_eq!(
        complete_reset(&db, &env, &challenge, false, 9)
            .await
            .unwrap(),
        PasswordResetOutcome::Refused
    );
    let expected = "/authorize?client_id=fixture".to_string();
    assert_eq!(
        complete_reset(&db, &env, &challenge, true, 9)
            .await
            .unwrap(),
        PasswordResetOutcome::Completed {
            authorization_return_to: expected.clone()
        }
    );
    let store = db.store();
    let scoped = store.scoped(scope);
    assert_eq!(
        scoped
            .users()
            .password_hash_for_subject(&subject)
            .await
            .unwrap()
            .as_deref(),
        Some(NEW_HASH)
    );
    assert!(
        scoped
            .sessions()
            .get(&session, 0, 0)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        scoped
            .recovery_flows()
            .get(&recovery)
            .await
            .unwrap()
            .unwrap()
            .state,
        RecoveryState::Completed
    );
    let audit_before = scoped.audit().list().await.unwrap().len();
    let challenge = scoped
        .password_reset()
        .challenge(&env, &challenge.id, &[3; 32])
        .await
        .unwrap()
        .expect("lost-response retry can retrieve its browser-bound verifier");
    assert_eq!(
        complete_reset(&db, &env, &challenge, true, 9)
            .await
            .unwrap(),
        PasswordResetOutcome::Replayed {
            authorization_return_to: expected
        }
    );
    assert_eq!(
        complete_reset(&db, &env, &challenge, true, 8)
            .await
            .unwrap(),
        PasswordResetOutcome::Refused
    );
    assert_eq!(
        complete_reset(&db, &env, &challenge, false, 9)
            .await
            .unwrap(),
        PasswordResetOutcome::Refused
    );
    assert_eq!(scoped.audit().list().await.unwrap().len(), audit_before);
    let row = sqlx::query("SELECT state,attempt_count,completion_request_hash FROM password_reset_challenges WHERE id=$1")
        .bind(challenge.id.to_string()).fetch_one(db.owner_pool()).await.unwrap();
    assert_eq!(row.get::<String, _>("state"), "completed");
    assert_eq!(row.get::<i32, _>("attempt_count"), 2);
    assert_eq!(
        row.get::<Vec<u8>, _>("completion_request_hash"),
        vec![9; 32]
    );
}

#[tokio::test]
async fn reset_completion_refuses_a_correct_code_after_five_failures() {
    use ironauth_store::PasswordResetOutcome;
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (subject, _, challenge) = reset_fixture(&db, &env, scope).await;
    for _ in 0..5 {
        assert_eq!(
            complete_reset(&db, &env, &challenge, false, 9)
                .await
                .unwrap(),
            PasswordResetOutcome::Refused
        );
    }
    assert_eq!(
        complete_reset(&db, &env, &challenge, true, 9)
            .await
            .unwrap(),
        PasswordResetOutcome::Refused
    );
    assert_eq!(
        db.store()
            .scoped(scope)
            .users()
            .password_hash_for_subject(&subject)
            .await
            .unwrap()
            .as_deref(),
        Some(HASH)
    );
    let row = sqlx::query("SELECT state,attempt_count FROM password_reset_challenges WHERE id=$1")
        .bind(challenge.id.to_string())
        .fetch_one(db.owner_pool())
        .await
        .unwrap();
    assert_eq!(row.get::<String, _>("state"), "refused");
    assert_eq!(row.get::<i32, _>("attempt_count"), 5);
}

#[tokio::test]
async fn reset_completion_audit_failure_rolls_back_password_proof_case_and_sessions() {
    use ironauth_store::{PasswordResetOutcome, RecoveryState, StoreError};
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (subject, recovery, challenge) = reset_fixture(&db, &env, scope).await;
    let session = reset_session(&db, &env, &subject).await;
    let store = db.store();
    let scoped = store.scoped(scope);
    let audit_before = scoped.audit().list().await.unwrap().len();
    sqlx::raw_sql("CREATE FUNCTION reject_reset_audit() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.action='password_reset.complete' THEN RAISE EXCEPTION 'injected reset failure'; END IF; RETURN NEW; END $$;
        CREATE TRIGGER reject_reset_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_reset_audit();")
        .execute(db.owner_pool()).await.unwrap();
    assert!(matches!(
        complete_reset(&db, &env, &challenge, true, 9).await,
        Err(StoreError::Database(_))
    ));
    assert_eq!(
        scoped
            .users()
            .password_hash_for_subject(&subject)
            .await
            .unwrap()
            .as_deref(),
        Some(HASH)
    );
    assert!(
        scoped
            .sessions()
            .get(&session, 0, 0)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        scoped
            .recovery_flows()
            .get(&recovery)
            .await
            .unwrap()
            .unwrap()
            .state,
        RecoveryState::Initiated
    );
    assert_eq!(scoped.audit().list().await.unwrap().len(), audit_before);
    let row = sqlx::query("SELECT state,attempt_count,completion_request_hash FROM password_reset_challenges WHERE id=$1")
        .bind(challenge.id.to_string()).fetch_one(db.owner_pool()).await.unwrap();
    assert_eq!(row.get::<String, _>("state"), "pending");
    assert_eq!(row.get::<i32, _>("attempt_count"), 0);
    assert!(
        row.get::<Option<Vec<u8>>, _>("completion_request_hash")
            .is_none()
    );
    sqlx::raw_sql(
        "DROP TRIGGER reject_reset_audit ON audit_log; DROP FUNCTION reject_reset_audit();",
    )
    .execute(db.owner_pool())
    .await
    .unwrap();
    assert!(matches!(
        complete_reset(&db, &env, &challenge, true, 9)
            .await
            .unwrap(),
        PasswordResetOutcome::Completed { .. }
    ));
}

#[tokio::test]
async fn reset_completion_concurrent_exact_retry_changes_credential_once() {
    use ironauth_store::PasswordResetOutcome;
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (_, _, challenge) = reset_fixture(&db, &env, scope).await;
    let (a, b) = tokio::join!(
        complete_reset(&db, &env, &challenge, true, 9),
        complete_reset(&db, &env, &challenge, true, 9)
    );
    let outcomes = [a.unwrap(), b.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| matches!(o, PasswordResetOutcome::Completed { .. }))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| matches!(o, PasswordResetOutcome::Replayed { .. }))
            .count(),
        1
    );
    assert_eq!(
        db.store()
            .scoped(scope)
            .audit()
            .list()
            .await
            .unwrap()
            .iter()
            .filter(|row| row.action == "password_reset.complete")
            .count(),
        1
    );
}

#[tokio::test]
async fn reset_completion_refuses_password_changes_and_cancelled_cases_after_issuance() {
    use ironauth_store::{CorrelationId, PasswordResetOutcome, RecoveryCancelReason};
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (subject, _, challenge) = reset_fixture(&db, &env, scope).await;
    let store = db.store();
    let acting = store
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env));
    acting
        .users()
        .change_password(&env, &subject, NEW_HASH, None, "fixture_password_change")
        .await
        .unwrap();
    assert_eq!(
        complete_reset(&db, &env, &challenge, true, 9)
            .await
            .unwrap(),
        PasswordResetOutcome::Refused
    );
    let other_scope = db.seed_scope(&env).await;
    let (other, recovery, cancelled) = reset_fixture(&db, &env, other_scope).await;
    store
        .scoped(other_scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .recovery_flows()
        .cancel(&env, &recovery, RecoveryCancelReason::UserNotification)
        .await
        .unwrap();
    assert_eq!(
        complete_reset(&db, &env, &cancelled, true, 9)
            .await
            .unwrap(),
        PasswordResetOutcome::Refused
    );
    assert_eq!(
        store
            .scoped(other_scope)
            .users()
            .password_hash_for_subject(&other)
            .await
            .unwrap()
            .as_deref(),
        Some(HASH)
    );
    for s in [scope, other_scope] {
        assert!(
            !store
                .scoped(s)
                .audit()
                .list()
                .await
                .unwrap()
                .iter()
                .any(|row| row.action == "password_reset.complete")
        );
    }
}

#[tokio::test]
async fn reset_completion_obeys_held_case_and_never_accepts_expired_proof() {
    use ironauth_store::PasswordResetOutcome;
    use std::time::{Duration, SystemTime};
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH + Duration::from_secs(1000), 1480);
    let scope = db.seed_scope(&env).await;
    let (subject, recovery, challenge) = reset_fixture(&db, &env, scope).await;
    let hold = now_micros(&env) + 120_000_000;
    sqlx::query("UPDATE recovery_flows SET state='held',hold_until=TIMESTAMPTZ 'epoch'+($2::text||' microseconds')::interval WHERE id=$1")
        .bind(recovery.to_string()).bind(hold).execute(db.owner_pool()).await.unwrap();
    assert_eq!(
        complete_reset(&db, &env, &challenge, true, 9)
            .await
            .unwrap(),
        PasswordResetOutcome::Held {
            until_unix_micros: hold
        }
    );
    assert_eq!(
        db.store()
            .scoped(scope)
            .users()
            .password_hash_for_subject(&subject)
            .await
            .unwrap()
            .as_deref(),
        Some(HASH)
    );
    clock.advance(Duration::from_secs(120));
    assert!(matches!(
        complete_reset(&db, &env, &challenge, true, 9)
            .await
            .unwrap(),
        PasswordResetOutcome::Completed { .. }
    ));
    let other_scope = db.seed_scope(&env).await;
    let (other, _, expired) = reset_fixture(&db, &env, other_scope).await;
    clock.advance(Duration::from_secs(300));
    assert_eq!(
        complete_reset(&db, &env, &expired, true, 9).await.unwrap(),
        PasswordResetOutcome::Refused
    );
    assert_eq!(
        db.store()
            .scoped(other_scope)
            .users()
            .password_hash_for_subject(&other)
            .await
            .unwrap()
            .as_deref(),
        Some(HASH)
    );
}

async fn reset_offline_grant(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    subject: &str,
    session_ref: Option<&ironauth_store::SessionId>,
) -> ironauth_store::GrantId {
    use ironauth_store::{
        AuthorizationCodeId, ClientId, CorrelationId, GrantId, IssueCode, SessionId, StoredClientId,
    };
    let code_id = AuthorizationCodeId::generate(env, &scope);
    let grant_id = GrantId::generate(env, &scope);
    let client_id = ClientId::generate(env, &scope);
    let session = session_ref.map(SessionId::to_string);
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .authorization()
        .issue(
            env,
            IssueCode {
                code_id: &code_id,
                grant_id: &grant_id,
                client_id: StoredClientId::Registered(&client_id),
                redirect_uri: "https://client.test/cb",
                browserless: false,
                nonce: None,
                code_challenge: None,
                code_challenge_method: None,
                subject,
                oauth_scope: Some("openid"),
                auth_methods: "pwd",
                auth_time_micros: None,
                session_ref: session.as_deref(),
                org_id: None,
                consent_ref: None,
                claims_request: None,
                granted_resources: &[],
                // Not sender-constrained (issue #368): these fixtures predate the
                // binding and exercise paths that never set it.
                dpop_jkt: None,
                expires_at_micros: 4_102_444_800_000_000,
                created_at_micros: 0,
            },
        )
        .await
        .expect("issue code");
    grant_id
}

#[tokio::test]
async fn reset_completion_revokes_offline_family_grant_and_remembered_device() {
    use ironauth_store::{PasswordResetOutcome, StoreError};
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (subject, _, challenge) = reset_fixture(&db, &env, scope).await;
    let session = reset_session(&db, &env, &subject).await;
    let (family, device) = reset_access_fixture(&db, &env, &subject, &session).await;
    let store = db.store();
    let scoped = store.scoped(scope);
    assert!(
        scoped
            .trusted_devices()
            .validate(&device, &subject, &[5; 32], now_micros(&env))
            .await
            .unwrap()
            .is_some()
    );
    let audit_before = scoped.audit().list().await.unwrap().len();
    reset_audit_fault(&db, true).await;
    assert!(matches!(
        complete_reset(&db, &env, &challenge, true, 9).await,
        Err(StoreError::Database(_))
    ));
    assert_eq!(reset_refresh_revoked(&db, &family).await, (false, false));
    assert!(
        scoped
            .trusted_devices()
            .validate(&device, &subject, &[5; 32], now_micros(&env))
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        scoped
            .sessions()
            .get(&session, 0, 0)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        scoped
            .session_events()
            .pending(100)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(scoped.audit().list().await.unwrap().len(), audit_before);
    reset_audit_fault(&db, false).await;
    assert!(matches!(
        complete_reset(&db, &env, &challenge, true, 9)
            .await
            .unwrap(),
        PasswordResetOutcome::Completed { .. }
    ));
    assert!(
        scoped
            .trusted_devices()
            .validate(&device, &subject, &[5; 32], now_micros(&env))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(reset_refresh_revoked(&db, &family).await, (true, true));
    let events = scoped.session_events().pending(100).await.unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].session_id, session.to_string());
    assert_eq!(
        events[0].cause,
        ironauth_store::SessionEndCause::PasswordChanged
    );
}

#[tokio::test]
async fn reset_completion_refuses_a_held_case_without_its_delay_horizon() {
    use ironauth_store::PasswordResetOutcome;
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (subject, recovery, challenge) = reset_fixture(&db, &env, scope).await;
    sqlx::query("UPDATE recovery_flows SET state='held',hold_until=NULL WHERE id=$1")
        .bind(recovery.to_string())
        .execute(db.owner_pool())
        .await
        .unwrap();
    assert_eq!(
        complete_reset(&db, &env, &challenge, true, 9)
            .await
            .unwrap(),
        PasswordResetOutcome::Refused
    );
    assert_eq!(
        db.store()
            .scoped(scope)
            .users()
            .password_hash_for_subject(&subject)
            .await
            .unwrap()
            .as_deref(),
        Some(HASH)
    );
}

#[tokio::test]
async fn reset_pending_proof_and_completed_receipt_reject_a_new_mailbox_verification_epoch() {
    use ironauth_store::PasswordResetOutcome;
    use std::time::{Duration, SystemTime};
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH + Duration::from_secs(1000), 1481);
    let scope = db.seed_scope(&env).await;
    let (subject, _, pending) = reset_fixture(&db, &env, scope).await;
    let other_scope = db.seed_scope(&env).await;
    let (other, _, completed) = reset_fixture(&db, &env, other_scope).await;
    assert!(matches!(
        complete_reset(&db, &env, &completed, true, 9)
            .await
            .unwrap(),
        PasswordResetOutcome::Completed { .. }
    ));
    clock.advance(Duration::from_secs(61));
    verify_reset_mailbox(&db, &env, &subject).await;
    verify_reset_mailbox(&db, &env, &other).await;
    assert_eq!(
        complete_reset(&db, &env, &pending, true, 9).await.unwrap(),
        PasswordResetOutcome::Refused
    );
    assert_eq!(
        complete_reset(&db, &env, &completed, true, 9)
            .await
            .unwrap(),
        PasswordResetOutcome::Refused
    );
    assert_eq!(
        db.store()
            .scoped(scope)
            .users()
            .password_hash_for_subject(&subject)
            .await
            .unwrap()
            .as_deref(),
        Some(HASH)
    );
    assert_eq!(
        db.store()
            .scoped(other_scope)
            .users()
            .password_hash_for_subject(&other)
            .await
            .unwrap()
            .as_deref(),
        Some(NEW_HASH)
    );
}

#[tokio::test]
async fn reset_completed_receipt_cannot_overwrite_a_later_password_change() {
    use ironauth_store::{CorrelationId, PasswordResetOutcome};
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (subject, _, challenge) = reset_fixture(&db, &env, scope).await;
    assert!(matches!(
        complete_reset(&db, &env, &challenge, true, 9)
            .await
            .unwrap(),
        PasswordResetOutcome::Completed { .. }
    ));
    let store = db.store();
    let scoped = store.scoped(scope);
    scoped
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .users()
        .change_password(&env, &subject, HASH, None, "fixture_later_password_change")
        .await
        .unwrap();
    assert_eq!(
        complete_reset(&db, &env, &challenge, true, 9)
            .await
            .unwrap(),
        PasswordResetOutcome::Refused
    );
    assert_eq!(
        scoped
            .users()
            .password_hash_for_subject(&subject)
            .await
            .unwrap()
            .as_deref(),
        Some(HASH)
    );
    assert_eq!(
        scoped
            .audit()
            .list()
            .await
            .unwrap()
            .iter()
            .filter(|row| row.action == "password_reset.complete")
            .count(),
        1
    );
}

#[tokio::test]
async fn reset_completion_rejects_wrong_browser_scope_and_verifier_snapshot_without_spending_attempts()
 {
    use ironauth_store::{
        CompletePasswordReset, CorrelationId, PasswordResetChallenge, PasswordResetOutcome,
    };
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let other = db.seed_scope(&env).await;
    let (subject, _, challenge) = reset_fixture(&db, &env, scope).await;
    for (request_scope, binding) in [(other, [3; 32]), (scope, [4; 32])] {
        assert_eq!(
            db.store()
                .scoped(request_scope)
                .acting(db.test_actor(&env), CorrelationId::generate(&env))
                .password_reset()
                .complete(
                    &env,
                    CompletePasswordReset {
                        challenge: &challenge,
                        browser_binding_hash: &binding,
                        code_matched: true,
                        new_password_hash: NEW_HASH,
                        request_hash: &[9; 32],
                    }
                )
                .await
                .unwrap(),
            PasswordResetOutcome::Refused
        );
    }
    let forged = PasswordResetChallenge {
        id: challenge.id,
        code_hash: NEW_HASH.to_string(),
    };
    assert_eq!(
        complete_reset(&db, &env, &forged, true, 9).await.unwrap(),
        PasswordResetOutcome::Refused
    );
    let count: i32 =
        sqlx::query_scalar("SELECT attempt_count FROM password_reset_challenges WHERE id=$1")
            .bind(challenge.id.to_string())
            .fetch_one(db.owner_pool())
            .await
            .unwrap();
    assert_eq!(count, 0);
    assert_eq!(
        db.store()
            .scoped(scope)
            .users()
            .password_hash_for_subject(&subject)
            .await
            .unwrap()
            .as_deref(),
        Some(HASH)
    );
}

async fn reset_access_fixture(
    db: &TestDatabase,
    env: &Env,
    subject: &ironauth_store::UserId,
    session: &ironauth_store::SessionId,
) -> (
    ironauth_store::RefreshFamilyId,
    ironauth_store::TrustedDeviceId,
) {
    use ironauth_store::{
        CorrelationId, NewRefreshFamily, NewTrustedDevice, RefreshFamilyId, RefreshTokenId,
        refresh_token_digest,
    };
    let scope = subject.scope();
    let grant = reset_offline_grant(db, env, scope, &subject.to_string(), Some(session)).await;
    let store = db.store();
    let scoped = store.scoped(scope);
    let acting = scoped.acting(db.test_actor(env), CorrelationId::generate(env));
    let family = RefreshFamilyId::generate(env, &scope);
    let token = RefreshTokenId::generate(env, &scope);
    acting
        .refresh()
        .issue(
            env,
            NewRefreshFamily {
                family_id: &family,
                token_jti: &token,
                token_digest: &refresh_token_digest("fixture-refresh"),
                grant_id: &grant,
                subject: &subject.to_string(),
                client_id: "cli_family",
                scope: Some("openid offline_access"),
                auth_methods: "pwd",
                auth_time_unix_micros: None,
                offline: true,
                created_at_unix_micros: now_micros(env),
                idle_expires_at_unix_micros: 4_102_444_800_000_000,
                absolute_expires_at_unix_micros: 4_102_444_800_000_000,
                dpop_jkt: None,
            },
        )
        .await
        .unwrap();
    let device = acting
        .trusted_devices()
        .remember(
            env,
            subject,
            NewTrustedDevice {
                device_secret_hash: &[5; 32],
                session_lineage: &session.to_string(),
                user_agent: "isolated reset fixture",
                coarse_location: "fixture",
                max_age_expires_micros: 4_102_444_800_000_000,
                idle_expires_micros: 4_102_444_800_000_000,
            },
        )
        .await
        .unwrap();
    (family, device)
}

async fn reset_refresh_revoked(
    db: &TestDatabase,
    family: &ironauth_store::RefreshFamilyId,
) -> (bool, bool) {
    let row = sqlx::query("SELECT f.revoked_at IS NOT NULL AS family_revoked,g.revoked_at IS NOT NULL AS grant_revoked FROM refresh_families f JOIN grants g ON g.id=f.grant_id WHERE f.id=$1")
        .bind(family.to_string()).fetch_one(db.owner_pool()).await.unwrap();
    (row.get("family_revoked"), row.get("grant_revoked"))
}

async fn reset_audit_fault(db: &TestDatabase, enabled: bool) {
    let sql = if enabled {
        "CREATE FUNCTION reject_reset_audit() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.action='password_reset.complete' THEN RAISE EXCEPTION 'injected reset failure'; END IF; RETURN NEW; END $$;
        CREATE TRIGGER reject_reset_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_reset_audit();"
    } else {
        "DROP TRIGGER reject_reset_audit ON audit_log; DROP FUNCTION reject_reset_audit();"
    };
    sqlx::raw_sql(sql).execute(db.owner_pool()).await.unwrap();
}

#[tokio::test]
async fn reset_completion_and_cancellation_have_one_committed_winner() {
    use ironauth_store::{
        CorrelationId, PasswordResetOutcome, RecoveryCancelReason, RecoveryState,
    };
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (subject, recovery, challenge) = reset_fixture(&db, &env, scope).await;
    let store = db.store();
    let scoped = store.scoped(scope);
    let acting = scoped.acting(db.test_actor(&env), CorrelationId::generate(&env));
    let cases = acting.recovery_flows();
    let results = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(
            complete_reset(&db, &env, &challenge, true, 9),
            cases.cancel(&env, &recovery, RecoveryCancelReason::UserNotification)
        )
    })
    .await
    .expect("completion/cancellation must not deadlock");
    let (completion, cancelled) = (results.0.unwrap(), results.1.unwrap());
    let state = scoped
        .recovery_flows()
        .get(&recovery)
        .await
        .unwrap()
        .unwrap()
        .state;
    let password = scoped
        .users()
        .password_hash_for_subject(&subject)
        .await
        .unwrap()
        .unwrap();
    if cancelled {
        assert_eq!(completion, PasswordResetOutcome::Refused);
        assert_eq!(state, RecoveryState::Cancelled);
        assert_eq!(password, HASH);
    } else {
        assert!(matches!(completion, PasswordResetOutcome::Completed { .. }));
        assert_eq!(state, RecoveryState::Completed);
        assert_eq!(password, NEW_HASH);
    }
}

#[tokio::test]
async fn reset_completion_racing_password_change_never_overwrites_the_later_generation() {
    use ironauth_store::{CorrelationId, PasswordResetOutcome};
    const LATER_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$dGhpcmRzYWx0$dGhpcmRoYXNo";
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (subject, _, challenge) = reset_fixture(&db, &env, scope).await;
    let _session = reset_session(&db, &env, &subject).await;
    let store = db.store();
    let scoped = store.scoped(scope);
    let acting = scoped.acting(db.test_actor(&env), CorrelationId::generate(&env));
    let users = acting.users();
    let results = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(
            complete_reset(&db, &env, &challenge, true, 9),
            users.change_password(
                &env,
                &subject,
                LATER_HASH,
                None,
                "fixture_concurrent_change"
            )
        )
    })
    .await
    .expect("completion/password change must not deadlock");
    results.1.unwrap();
    assert!(matches!(
        results.0.unwrap(),
        PasswordResetOutcome::Completed { .. } | PasswordResetOutcome::Refused
    ));
    assert_eq!(
        scoped
            .users()
            .password_hash_for_subject(&subject)
            .await
            .unwrap()
            .as_deref(),
        Some(LATER_HASH)
    );
    assert_eq!(
        complete_reset(&db, &env, &challenge, true, 9)
            .await
            .unwrap(),
        PasswordResetOutcome::Refused
    );
}

#[tokio::test]
async fn reset_completion_requires_durable_acceptance_of_required_notifications() {
    use ironauth_store::{PasswordResetDelivery, PasswordResetOutcome, StoreError};
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (subject, _, challenge) = pending_reset_fixture(&db, &env, scope).await;
    assert_eq!(
        complete_reset(&db, &env, &challenge, true, 9)
            .await
            .unwrap(),
        PasswordResetOutcome::Refused
    );
    assert_eq!(
        db.store()
            .scoped(scope)
            .users()
            .password_hash_for_subject(&subject)
            .await
            .unwrap()
            .as_deref(),
        Some(HASH)
    );
    assert!(matches!(
        record_reset_delivery(&db, &env, &challenge.id, PasswordResetDelivery::Accepted, 0).await,
        Err(StoreError::Invalid)
    ));
    record_reset_delivery(&db, &env, &challenge.id, PasswordResetDelivery::Accepted, 1)
        .await
        .unwrap();
    assert!(matches!(
        record_reset_delivery(&db, &env, &challenge.id, PasswordResetDelivery::Accepted, 1).await,
        Err(StoreError::Conflict)
    ));
    assert!(matches!(
        complete_reset(&db, &env, &challenge, true, 9)
            .await
            .unwrap(),
        PasswordResetOutcome::Completed { .. }
    ));
    assert_eq!(
        db.store()
            .scoped(scope)
            .audit()
            .list()
            .await
            .unwrap()
            .iter()
            .filter(|row| row.action == "password_reset.delivery")
            .count(),
        1
    );
}

#[tokio::test]
async fn reset_refused_or_uncertain_delivery_cannot_be_relabelled_as_accepted() {
    use ironauth_store::{PasswordResetDelivery, PasswordResetOutcome, StoreError};
    let db = TestDatabase::start().await;
    let env = Env::system();
    for delivery in [
        PasswordResetDelivery::Refused,
        PasswordResetDelivery::Uncertain,
    ] {
        let scope = db.seed_scope(&env).await;
        let (subject, _, challenge) = pending_reset_fixture(&db, &env, scope).await;
        record_reset_delivery(&db, &env, &challenge.id, delivery, 0)
            .await
            .unwrap();
        assert!(matches!(
            record_reset_delivery(&db, &env, &challenge.id, PasswordResetDelivery::Accepted, 1)
                .await,
            Err(StoreError::Conflict)
        ));
        assert_eq!(
            complete_reset(&db, &env, &challenge, true, 9)
                .await
                .unwrap(),
            PasswordResetOutcome::Refused
        );
        assert_eq!(
            db.store()
                .scoped(scope)
                .users()
                .password_hash_for_subject(&subject)
                .await
                .unwrap()
                .as_deref(),
            Some(HASH)
        );
        let row = sqlx::query(
            "SELECT delivery_state,attempt_count FROM password_reset_challenges WHERE id=$1",
        )
        .bind(challenge.id.to_string())
        .fetch_one(db.owner_pool())
        .await
        .unwrap();
        assert_eq!(row.get::<String, _>("delivery_state"), delivery.as_str());
        assert_eq!(row.get::<i32, _>("attempt_count"), 0);
    }
}

#[tokio::test]
async fn reset_undelivered_decoy_still_has_the_same_wrong_code_attempt_budget() {
    use ironauth_store::PasswordResetOutcome;
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let id = PasswordResetChallengeId::generate(&env, &scope);
    start_reset(&db, &env, &id, None).await.unwrap();
    let challenge = db
        .store()
        .scoped(scope)
        .password_reset()
        .challenge(&env, &id, &[3; 32])
        .await
        .unwrap()
        .unwrap();
    for _ in 0..6 {
        assert_eq!(
            complete_reset(&db, &env, &challenge, false, 9)
                .await
                .unwrap(),
            PasswordResetOutcome::Refused
        );
    }
    let count: i32 =
        sqlx::query_scalar("SELECT attempt_count FROM password_reset_challenges WHERE id=$1")
            .bind(id.to_string())
            .fetch_one(db.owner_pool())
            .await
            .unwrap();
    assert_eq!(count, 5);
}

#[tokio::test]
async fn reset_delivery_audit_failure_rolls_back_acceptance_and_retry_commits_once() {
    use ironauth_store::{CorrelationId, PasswordResetDelivery, PasswordResetOutcome, StoreError};
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let foreign = db.seed_scope(&env).await;
    let (_, _, challenge) = pending_reset_fixture(&db, &env, scope).await;
    assert!(matches!(
        db.store()
            .scoped(foreign)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .password_reset()
            .record_delivery(&env, &challenge.id, PasswordResetDelivery::Accepted, 1)
            .await,
        Err(StoreError::NotFound)
    ));
    sqlx::raw_sql("CREATE FUNCTION reject_delivery_audit() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.action='password_reset.delivery' THEN RAISE EXCEPTION 'injected delivery audit failure'; END IF; RETURN NEW; END $$;
        CREATE TRIGGER reject_delivery_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_delivery_audit();")
        .execute(db.owner_pool()).await.unwrap();
    assert!(
        record_reset_delivery(&db, &env, &challenge.id, PasswordResetDelivery::Accepted, 1)
            .await
            .is_err()
    );
    let row = sqlx::query("SELECT delivery_state,notified_channels,delivery_finished_at IS NULL AS unfinished FROM password_reset_challenges WHERE id=$1")
        .bind(challenge.id.to_string()).fetch_one(db.owner_pool()).await.unwrap();
    assert_eq!(row.get::<String, _>("delivery_state"), "pending");
    assert_eq!(row.get::<i32, _>("notified_channels"), 0);
    assert!(row.get::<bool, _>("unfinished"));
    assert_eq!(
        complete_reset(&db, &env, &challenge, true, 9)
            .await
            .unwrap(),
        PasswordResetOutcome::Refused
    );
    assert_eq!(
        db.store()
            .scoped(scope)
            .audit()
            .list()
            .await
            .unwrap()
            .iter()
            .filter(|row| row.action == "password_reset.delivery")
            .count(),
        0
    );
    sqlx::raw_sql(
        "DROP TRIGGER reject_delivery_audit ON audit_log; DROP FUNCTION reject_delivery_audit();",
    )
    .execute(db.owner_pool())
    .await
    .unwrap();
    // Retry persisting the already observed transport result, not sending mail again.
    record_reset_delivery(&db, &env, &challenge.id, PasswordResetDelivery::Accepted, 1)
        .await
        .unwrap();
    assert!(matches!(
        complete_reset(&db, &env, &challenge, true, 9)
            .await
            .unwrap(),
        PasswordResetOutcome::Completed { .. }
    ));
    assert_eq!(
        db.store()
            .scoped(scope)
            .audit()
            .list()
            .await
            .unwrap()
            .iter()
            .filter(|row| row.action == "password_reset.delivery")
            .count(),
        1
    );
}

async fn start_case_reset(
    db: &TestDatabase,
    env: &Env,
    id: &PasswordResetChallengeId,
    subject: &ironauth_store::UserId,
    case: &ironauth_store::RecoveryFlowId,
) {
    start_reset(
        db,
        env,
        id,
        Some(ironauth_store::PasswordResetAccount {
            subject,
            recovery: case,
        }),
    )
    .await
    .unwrap();
}

async fn settle_reissued_case(
    db: &TestDatabase,
    env: &Env,
    old_digest: &[u8],
    challenge: &ironauth_store::PasswordResetChallenge,
    cancel: bool,
) {
    use ironauth_store::{CorrelationId, PasswordResetOutcome, RecoveryCancelReason};
    let scoped = db.store().scoped(challenge.id.scope());
    if cancel {
        let record = scoped
            .recovery_flows()
            .by_cancel_digest(old_digest)
            .await
            .unwrap()
            .unwrap();
        assert!(
            scoped
                .acting(db.test_actor(env), CorrelationId::generate(env))
                .recovery_flows()
                .cancel(env, &record.id, RecoveryCancelReason::UserNotification)
                .await
                .unwrap()
        );
        assert_eq!(
            complete_reset(db, env, challenge, true, 9).await.unwrap(),
            PasswordResetOutcome::Refused
        );
    } else {
        assert!(matches!(
            complete_reset(db, env, challenge, true, 9).await.unwrap(),
            PasswordResetOutcome::Completed { .. }
        ));
    }
}

#[tokio::test]
async fn reset_reissue_preserves_case_delay_and_expired_code_cancellation_links() {
    use ironauth_store::{PasswordResetDelivery, PasswordResetOutcome};
    use sha2::{Digest, Sha256};
    use std::time::{Duration, SystemTime};
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH + Duration::from_secs(1000), 1485);
    for cancel in [true, false] {
        let scope = db.seed_scope(&env).await;
        let other = db.seed_scope(&env).await;
        let (subject, case, old) = reset_fixture(&db, &env, scope).await;
        let hold = now_micros(&env) + 3_600_000_000;
        sqlx::query("UPDATE recovery_flows SET state='held',hold_until=TIMESTAMPTZ 'epoch'+($2::text||' microseconds')::interval WHERE id=$1")
            .bind(case.to_string()).bind(hold).execute(db.owner_pool()).await.unwrap();
        assert_eq!(
            complete_reset(&db, &env, &old, true, 9).await.unwrap(),
            PasswordResetOutcome::Held {
                until_unix_micros: hold
            }
        );
        clock.advance(Duration::from_secs(3601));
        let next = PasswordResetChallengeId::generate(&env, &scope);
        start_case_reset(&db, &env, &next, &subject, &case).await;
        record_reset_delivery(&db, &env, &next, PasswordResetDelivery::Accepted, 1)
            .await
            .unwrap();
        let store = db.store();
        let scoped = store.scoped(scope);
        let challenge = scoped
            .password_reset()
            .challenge(&env, &next, &[3; 32])
            .await
            .unwrap()
            .unwrap();
        assert!(
            scoped
                .password_reset()
                .challenge(&env, &old.id, &[3; 32])
                .await
                .unwrap()
                .is_none()
        );
        let old_digest = Sha256::digest(old.id.to_string());
        let new_digest = Sha256::digest(next.to_string());
        for digest in [old_digest.as_slice(), new_digest.as_slice(), &[7; 32]] {
            let record = scoped
                .recovery_flows()
                .by_cancel_digest(digest)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(record.id, case);
            assert_eq!(record.hold_until_unix_micros, Some(hold));
            assert!(record.state.is_pending());
            assert!(
                store
                    .scoped(other)
                    .recovery_flows()
                    .by_cancel_digest(digest)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        settle_reissued_case(&db, &env, &old_digest, &challenge, cancel).await;
        for digest in [old_digest.as_slice(), new_digest.as_slice()] {
            assert!(
                !scoped
                    .recovery_flows()
                    .by_cancel_digest(digest)
                    .await
                    .unwrap()
                    .unwrap()
                    .state
                    .is_pending()
            );
        }
    }
}

#[tokio::test]
async fn reset_first_accepted_notice_starts_full_delay_and_resends_do_not_restart_it() {
    use ironauth_store::{PasswordResetDelivery, PasswordResetOutcome};
    use std::time::{Duration, SystemTime};
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH + Duration::from_secs(1000), 1487);
    let scope = db.seed_scope(&env).await;
    let (subject, case, first) = pending_reset_fixture(&db, &env, scope).await;
    let initial_hold = now_micros(&env) + 3_600_000_000;
    sqlx::query("UPDATE recovery_flows SET state='held',hold_until=TIMESTAMPTZ 'epoch'+($2::text||' microseconds')::interval WHERE id=$1")
        .bind(case.to_string()).bind(initial_hold).execute(db.owner_pool()).await.unwrap();
    record_reset_delivery(&db, &env, &first.id, PasswordResetDelivery::Refused, 0)
        .await
        .unwrap();
    clock.advance(Duration::from_secs(3601));
    let fresh = PasswordResetChallengeId::generate(&env, &scope);
    start_case_reset(&db, &env, &fresh, &subject, &case).await;
    let notified_hold = now_micros(&env) + 3_600_000_000;
    sqlx::raw_sql("CREATE FUNCTION reject_notice_audit() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.action='password_reset.delivery' THEN RAISE EXCEPTION 'injected notice audit failure'; END IF; RETURN NEW; END $$;
        CREATE TRIGGER reject_notice_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_notice_audit();")
        .execute(db.owner_pool()).await.unwrap();
    assert!(
        record_reset_delivery(&db, &env, &fresh, PasswordResetDelivery::Accepted, 1)
            .await
            .is_err()
    );
    assert_eq!(
        db.store()
            .scoped(scope)
            .recovery_flows()
            .by_cancel_digest(&[7; 32])
            .await
            .unwrap()
            .unwrap()
            .hold_until_unix_micros,
        Some(initial_hold)
    );
    sqlx::raw_sql(
        "DROP TRIGGER reject_notice_audit ON audit_log; DROP FUNCTION reject_notice_audit();",
    )
    .execute(db.owner_pool())
    .await
    .unwrap();
    record_reset_delivery(&db, &env, &fresh, PasswordResetDelivery::Accepted, 1)
        .await
        .unwrap();
    let store = db.store();
    let scoped = store.scoped(scope);
    let challenge = scoped
        .password_reset()
        .challenge(&env, &fresh, &[3; 32])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        complete_reset(&db, &env, &challenge, true, 9)
            .await
            .unwrap(),
        PasswordResetOutcome::Held {
            until_unix_micros: notified_hold
        }
    );
    // A resend inside the waiting period retains the first accepted notice's horizon.
    clock.advance(Duration::from_secs(61));
    let resend = PasswordResetChallengeId::generate(&env, &scope);
    start_case_reset(&db, &env, &resend, &subject, &case).await;
    record_reset_delivery(&db, &env, &resend, PasswordResetDelivery::Accepted, 1)
        .await
        .unwrap();
    assert_eq!(
        scoped
            .recovery_flows()
            .by_cancel_digest(&[7; 32])
            .await
            .unwrap()
            .unwrap()
            .hold_until_unix_micros,
        Some(notified_hold)
    );
    // The final fresh code can complete exactly when the notified delay has elapsed.
    clock.advance(Duration::from_secs(3539));
    let ready = PasswordResetChallengeId::generate(&env, &scope);
    start_case_reset(&db, &env, &ready, &subject, &case).await;
    record_reset_delivery(&db, &env, &ready, PasswordResetDelivery::Accepted, 1)
        .await
        .unwrap();
    let challenge = scoped
        .password_reset()
        .challenge(&env, &ready, &[3; 32])
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        complete_reset(&db, &env, &challenge, true, 9)
            .await
            .unwrap(),
        PasswordResetOutcome::Completed { .. }
    ));
}

#[tokio::test]
async fn reset_delivery_claim_has_one_winner_and_cannot_be_replayed_after_interruption() {
    use ironauth_store::{CorrelationId, StoreError};
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (subject, _, challenge) = pending_reset_fixture(&db, &env, scope).await;
    let wrong = ironauth_store::UserId::generate(&env, &scope);
    let store = db.store();
    let acting = store
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env));
    assert!(matches!(
        acting
            .password_reset()
            .claim_delivery(&env, &challenge.id, &wrong)
            .await,
        Err(StoreError::Conflict)
    ));
    let first = acting.password_reset();
    let second = acting.password_reset();
    let (a, b) = tokio::join!(
        first.claim_delivery(&env, &challenge.id, &subject),
        second.claim_delivery(&env, &challenge.id, &subject)
    );
    assert_ne!(a.is_ok(), b.is_ok());
    assert!(matches!(
        if a.is_err() { a } else { b },
        Err(StoreError::Conflict)
    ));
    let restarted = store
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env));
    assert!(matches!(
        restarted
            .password_reset()
            .claim_delivery(&env, &challenge.id, &subject)
            .await,
        Err(StoreError::Conflict)
    ));
    let row = sqlx::query("SELECT delivery_state,delivery_started_at IS NOT NULL AS started FROM password_reset_challenges WHERE id=$1")
        .bind(challenge.id.to_string()).fetch_one(db.owner_pool()).await.unwrap();
    assert_eq!(row.get::<String, _>("delivery_state"), "pending");
    assert!(row.get::<bool, _>("started"));
    assert_eq!(
        store
            .scoped(scope)
            .audit()
            .list()
            .await
            .unwrap()
            .iter()
            .filter(|row| row.action == "password_reset.delivery_started")
            .count(),
        1
    );
}

#[tokio::test]
async fn reset_context_retains_navigation_after_code_expiry_but_not_past_browser_window() {
    use std::time::{Duration, SystemTime};
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH + Duration::from_secs(1000), 1491);
    let scope = db.seed_scope(&env).await;
    let foreign = db.seed_scope(&env).await;
    let (subject, _, challenge) = pending_reset_fixture(&db, &env, scope).await;
    let decoy = PasswordResetChallengeId::generate(&env, &scope);
    start_reset(&db, &env, &decoy, None).await.unwrap();
    let store = db.store();
    let scoped = store.scoped(scope);
    let read = scoped.password_reset();
    assert!(
        read.context(&env, &challenge.id, &[4; 32])
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .scoped(foreign)
            .password_reset()
            .context(&env, &challenge.id, &[3; 32])
            .await
            .unwrap()
            .is_none()
    );
    let original = read
        .context(&env, &challenge.id, &[3; 32])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(original.created_at_unix_micros, now_micros(&env));
    assert_eq!(original.subject, Some(subject));
    assert_eq!(original.client.scope(), scope);
    assert_eq!(
        original.authorization_return_to,
        "/authorize?client_id=fixture"
    );
    assert_eq!(
        original.expires_at_unix_micros,
        now_micros(&env) + 300_000_000
    );
    // Losing the completion response must not lose this browser's navigation.
    record_reset_delivery(
        &db,
        &env,
        &challenge.id,
        ironauth_store::PasswordResetDelivery::Accepted,
        1,
    )
    .await
    .unwrap();
    assert!(matches!(
        complete_reset(&db, &env, &challenge, true, 9)
            .await
            .unwrap(),
        ironauth_store::PasswordResetOutcome::Completed { .. }
    ));
    assert_eq!(
        read.context(&env, &challenge.id, &[3; 32])
            .await
            .unwrap()
            .unwrap()
            .client,
        original.client
    );
    let audit_before = scoped.audit().list().await.unwrap().len();
    clock.advance(Duration::from_secs(300));
    for id in [&challenge.id, &decoy] {
        assert!(read.challenge(&env, id, &[3; 32]).await.unwrap().is_none());
        let context = read.context(&env, id, &[3; 32]).await.unwrap().unwrap();
        assert_eq!(
            context.created_at_unix_micros,
            original.created_at_unix_micros
        );
        assert_eq!(
            context.authorization_return_to,
            original.authorization_return_to
        );
        assert_eq!(
            context.expires_at_unix_micros,
            original.expires_at_unix_micros
        );
        assert_eq!(context.subject.is_some(), id == &challenge.id);
    }
    assert_eq!(scoped.audit().list().await.unwrap().len(), audit_before);
    clock.advance(Duration::from_secs(300));
    for id in [&challenge.id, &decoy] {
        assert!(read.context(&env, id, &[3; 32]).await.unwrap().is_none());
    }
}

#[tokio::test]
async fn reset_receipt_read_confirms_only_current_completed_exact_request_without_mutation() {
    use ironauth_store::{PasswordResetOutcome, PasswordResetReceipt};
    use std::time::{Duration, SystemTime};
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH + Duration::from_secs(1000), 1493);
    let scope = db.seed_scope(&env).await;
    let other = db.seed_scope(&env).await;
    let (subject, _, challenge) = reset_fixture(&db, &env, scope).await;
    let store = db.store();
    let scoped = store.scoped(scope);
    let read = scoped.password_reset();
    let before = scoped.audit().list().await.unwrap().len();
    assert!(
        read.receipt(
            &env,
            PasswordResetReceipt {
                challenge: &challenge,
                browser_binding_hash: &[3; 32],
                code_matched: true,
                request_hash: &[9; 32]
            }
        )
        .await
        .unwrap()
        .is_none()
    );
    let attempts: i32 =
        sqlx::query_scalar("SELECT attempt_count FROM password_reset_challenges WHERE id=$1")
            .bind(challenge.id.to_string())
            .fetch_one(db.owner_pool())
            .await
            .unwrap();
    assert_eq!(attempts, 0);
    assert_eq!(scoped.audit().list().await.unwrap().len(), before);
    assert!(matches!(
        complete_reset(&db, &env, &challenge, true, 9)
            .await
            .unwrap(),
        PasswordResetOutcome::Completed { .. }
    ));
    let completed_audits = scoped.audit().list().await.unwrap().len();
    for (request_scope, browser, matched, request, expected) in [
        (scope, [3; 32], true, [9; 32], true),
        (scope, [4; 32], true, [9; 32], false),
        (scope, [3; 32], false, [9; 32], false),
        (scope, [3; 32], true, [8; 32], false),
        (other, [3; 32], true, [9; 32], false),
    ] {
        let result = store
            .scoped(request_scope)
            .password_reset()
            .receipt(
                &env,
                PasswordResetReceipt {
                    challenge: &challenge,
                    browser_binding_hash: &browser,
                    code_matched: matched,
                    request_hash: &request,
                },
            )
            .await
            .unwrap();
        assert_eq!(result.is_some(), expected);
        if expected {
            assert_eq!(result.as_deref(), Some("/authorize?client_id=fixture"));
        }
    }
    assert_eq!(scoped.audit().list().await.unwrap().len(), completed_audits);
    assert_eq!(
        scoped
            .users()
            .password_hash_for_subject(&subject)
            .await
            .unwrap()
            .as_deref(),
        Some(NEW_HASH)
    );
    clock.advance(Duration::from_secs(61));
    verify_reset_mailbox(&db, &env, &subject).await;
    assert!(
        read.receipt(
            &env,
            PasswordResetReceipt {
                challenge: &challenge,
                browser_binding_hash: &[3; 32],
                code_matched: true,
                request_hash: &[9; 32]
            }
        )
        .await
        .unwrap()
        .is_none()
    );
}

async fn prepare_case(
    db: &TestDatabase,
    env: &Env,
    subject: &ironauth_store::UserId,
    delay_micros: i64,
) -> Result<ironauth_store::RecoveryFlowId, ironauth_store::StoreError> {
    use ironauth_store::{CorrelationId, PreparePasswordResetCase, RecoveryFlowId};
    use sha2::{Digest, Sha256};
    let scope = subject.scope();
    let id = RecoveryFlowId::generate(env, &scope);
    // Fixture only: the hosted caller hashes a high-entropy case-bound token.
    let digest: [u8; 32] = Sha256::digest(id.to_string()).into();
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .password_reset()
        .prepare_case(
            env,
            PreparePasswordResetCase {
                id: &id,
                subject,
                cancellation_token_digest: &digest,
                delay_micros,
                cooldown_micros: 60_000_000,
            },
        )
        .await
}

#[tokio::test]
async fn reset_case_preparation_serializes_creation_and_preserves_identity() {
    use std::time::Duration;
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = verified_account(&db, &env, scope).await;
    let (first, second) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            prepare_case(&db, &env, &subject, 0),
            prepare_case(&db, &env, &subject, 0)
        )
    })
    .await
    .expect("case preparation must not deadlock");
    let id = first.unwrap();
    assert_eq!(id, second.unwrap());
    assert_eq!(prepare_case(&db, &env, &subject, 0).await.unwrap(), id);
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM recovery_flows WHERE subject=$1")
        .bind(subject.to_string())
        .fetch_one(db.owner_pool())
        .await
        .unwrap();
    assert_eq!(rows, 1);
    let actions = db.store().scoped(scope).audit().list().await.unwrap();
    for action in ["recovery.initiate", "password_reset.case_prepare"] {
        assert_eq!(actions.iter().filter(|row| row.action == action).count(), 1);
    }
    let flow = db
        .store()
        .scoped(scope)
        .recovery_flows()
        .get(&id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(flow.state, ironauth_store::RecoveryState::Initiated);
    assert!(flow.hold_until_unix_micros.is_none());
    let challenges: i64 = sqlx::query_scalar("SELECT count(*) FROM password_reset_challenges")
        .fetch_one(db.owner_pool())
        .await
        .unwrap();
    assert_eq!(
        challenges, 0,
        "preparation does not issue or deliver a code"
    );
}

#[tokio::test]
async fn reset_case_preparation_keeps_notified_delay_and_monotonic_policy() {
    use ironauth_store::PasswordResetDelivery;
    use sha2::{Digest, Sha256};
    use std::time::{Duration, SystemTime};
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH + Duration::from_secs(1000), 1494);
    let scope = db.seed_scope(&env).await;
    let subject = verified_account(&db, &env, scope).await;
    let case = prepare_case(&db, &env, &subject, 3_600_000_000)
        .await
        .unwrap();
    clock.advance(Duration::from_secs(4000));
    assert_eq!(
        prepare_case(&db, &env, &subject, 3_600_000_000)
            .await
            .unwrap(),
        case
    );
    let id = PasswordResetChallengeId::generate(&env, &scope);
    start_case_reset(&db, &env, &id, &subject, &case).await;
    let accepted_at = now_micros(&env);
    record_reset_delivery(&db, &env, &id, PasswordResetDelivery::Accepted, 1)
        .await
        .unwrap();
    let cases = db.store().scoped(scope).recovery_flows();
    assert_eq!(
        cases
            .get(&case)
            .await
            .unwrap()
            .unwrap()
            .hold_until_unix_micros,
        Some(accepted_at + 3_600_000_000)
    );
    clock.advance(Duration::from_secs(3601));
    for delay in [3_600_000_000, 0] {
        assert_eq!(
            prepare_case(&db, &env, &subject, delay).await.unwrap(),
            case
        );
        assert_eq!(
            cases
                .get(&case)
                .await
                .unwrap()
                .unwrap()
                .hold_until_unix_micros,
            Some(accepted_at + 3_600_000_000)
        );
    }
    assert_eq!(
        prepare_case(&db, &env, &subject, 7_200_000_000)
            .await
            .unwrap(),
        case
    );
    assert_eq!(
        cases
            .get(&case)
            .await
            .unwrap()
            .unwrap()
            .hold_until_unix_micros,
        Some(accepted_at + 7_200_000_000)
    );
    let fresh = PasswordResetChallengeId::generate(&env, &scope);
    start_case_reset(&db, &env, &fresh, &subject, &case).await;
    record_reset_delivery(&db, &env, &fresh, PasswordResetDelivery::Accepted, 1)
        .await
        .unwrap();
    assert_eq!(
        cases
            .get(&case)
            .await
            .unwrap()
            .unwrap()
            .hold_until_unix_micros,
        Some(accepted_at + 7_200_000_000)
    );
    // Both old challenge cancellation aliases and the original case still exist.
    for handle in [id.to_string(), fresh.to_string(), case.to_string()] {
        assert_eq!(
            cases
                .by_cancel_digest(&Sha256::digest(handle))
                .await
                .unwrap()
                .unwrap()
                .id,
            case
        );
    }
}

#[tokio::test]
async fn reset_case_preparation_rolls_back_ineligibility_audit_failure_and_respects_cooldown() {
    use ironauth_store::{CorrelationId, RecoveryCancelReason, StoreError};
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acting = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env));
    let subject = acting
        .users()
        .register(&env, EMAIL, HASH, None)
        .await
        .unwrap();
    assert!(matches!(
        prepare_case(&db, &env, &subject, 0).await,
        Err(StoreError::NotFound)
    ));
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM recovery_flows")
        .fetch_one(db.owner_pool())
        .await
        .unwrap();
    assert_eq!(count, 0);
    verify_reset_mailbox(&db, &env, &subject).await;
    sqlx::raw_sql("CREATE FUNCTION reject_case_audit() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.action='password_reset.case_prepare' THEN RAISE EXCEPTION 'injected case audit failure'; END IF; RETURN NEW; END $$;
        CREATE TRIGGER reject_case_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_case_audit();")
        .execute(db.owner_pool()).await.unwrap();
    assert!(prepare_case(&db, &env, &subject, 0).await.is_err());
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM recovery_flows")
        .fetch_one(db.owner_pool())
        .await
        .unwrap();
    assert_eq!(count, 0);
    sqlx::raw_sql(
        "DROP TRIGGER reject_case_audit ON audit_log; DROP FUNCTION reject_case_audit();",
    )
    .execute(db.owner_pool())
    .await
    .unwrap();
    let id = prepare_case(&db, &env, &subject, 0).await.unwrap();
    assert!(
        acting
            .recovery_flows()
            .cancel(&env, &id, RecoveryCancelReason::UserNotification)
            .await
            .unwrap()
    );
    assert!(matches!(
        prepare_case(&db, &env, &subject, 0).await,
        Err(StoreError::Conflict)
    ));
    assert_eq!(
        db.store()
            .scoped(scope)
            .users()
            .password_hash_for_subject(&subject)
            .await
            .unwrap()
            .as_deref(),
        Some(HASH)
    );
}

#[tokio::test]
async fn reset_case_preparation_cannot_commit_policy_change_without_audit_or_cross_scope() {
    use ironauth_store::{CorrelationId, PreparePasswordResetCase, RecoveryFlowId, StoreError};
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let other = db.seed_scope(&env).await;
    let subject = verified_account(&db, &env, scope).await;
    let case = prepare_case(&db, &env, &subject, 0).await.unwrap();
    let before = db
        .store()
        .scoped(scope)
        .recovery_flows()
        .get(&case)
        .await
        .unwrap()
        .unwrap();
    let proposed = RecoveryFlowId::generate(&env, &other);
    assert!(matches!(
        db.store()
            .scoped(other)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .password_reset()
            .prepare_case(
                &env,
                PreparePasswordResetCase {
                    id: &proposed,
                    subject: &subject,
                    cancellation_token_digest: &[5; 32],
                    delay_micros: 1_000_000,
                    cooldown_micros: 0,
                }
            )
            .await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        prepare_case(&db, &env, &subject, -1).await,
        Err(StoreError::Invalid)
    ));
    sqlx::raw_sql("CREATE FUNCTION reject_case_audit() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.action='password_reset.case_prepare' THEN RAISE EXCEPTION 'injected case audit failure'; END IF; RETURN NEW; END $$;
        CREATE TRIGGER reject_case_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_case_audit();")
        .execute(db.owner_pool()).await.unwrap();
    assert!(
        prepare_case(&db, &env, &subject, 3_600_000_000)
            .await
            .is_err()
    );
    assert_eq!(
        db.store()
            .scoped(scope)
            .recovery_flows()
            .get(&case)
            .await
            .unwrap()
            .unwrap(),
        before
    );
    let duration: Option<i64> =
        sqlx::query_scalar("SELECT password_reset_delay_us FROM recovery_flows WHERE id=$1")
            .bind(case.to_string())
            .fetch_one(db.owner_pool())
            .await
            .unwrap();
    assert_eq!(duration, Some(0));
    sqlx::raw_sql(
        "DROP TRIGGER reject_case_audit ON audit_log; DROP FUNCTION reject_case_audit();",
    )
    .execute(db.owner_pool())
    .await
    .unwrap();
    assert_eq!(
        prepare_case(&db, &env, &subject, 3_600_000_000)
            .await
            .unwrap(),
        case
    );
    let after = db
        .store()
        .scoped(scope)
        .recovery_flows()
        .get(&case)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.state, ironauth_store::RecoveryState::Held);
    assert!(after.hold_until_unix_micros.is_some());
    assert_eq!(
        after.initiated_at_unix_micros,
        before.initiated_at_unix_micros
    );
}

#[tokio::test]
async fn reset_case_preparation_does_not_inherit_a_stronger_recovery_proof() {
    use ironauth_store::{
        CorrelationId, NewRecoveryFlow, RecoveryEntryPoint, RecoveryFlowId, RecoveryMethod,
    };
    use std::time::{Duration, SystemTime};
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH + Duration::from_secs(1000), 1495);
    let scope = db.seed_scope(&env).await;
    let subject = verified_account(&db, &env, scope).await;
    let strong = RecoveryFlowId::generate(&env, &scope);
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .recovery_flows()
        .initiate(
            &env,
            NewRecoveryFlow {
                id: &strong,
                subject: &subject,
                entry_point: RecoveryEntryPoint::LostPassword,
                recover_acr: "urn:ironauth:acr:mfa",
                cancel_token_digest: &[6; 32],
                recipient: EMAIL,
                hold_until_unix_micros: None,
                method: RecoveryMethod::Standard,
            },
            0,
        )
        .await
        .unwrap();
    clock.advance(Duration::from_secs(61));
    let reset = prepare_case(&db, &env, &subject, 0).await.unwrap();
    assert_ne!(reset, strong);
    let cases = db.store().scoped(scope).recovery_flows();
    assert_eq!(
        cases.get(&strong).await.unwrap().unwrap().recover_acr,
        "urn:ironauth:acr:mfa"
    );
    assert_eq!(
        cases.get(&reset).await.unwrap().unwrap().recover_acr,
        "urn:ironauth:acr:pwd"
    );
}

#[tokio::test]
async fn completion_notice_is_queued_once_and_claimed_once_after_commit() {
    use ironauth_store::{
        CorrelationId, PASSWORD_RESET_COMPLETION_CONSUMER, PasswordResetDelivery,
    };
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (subject, _, challenge) = reset_fixture(&db, &env, scope).await;
    let store = db.store();
    let scoped = store.scoped(scope);
    let acting = scoped.acting(db.test_actor(&env), CorrelationId::generate(&env));
    let notices = acting.password_reset();
    assert!(
        notices
            .claim_completion_notice(&env, &challenge.id)
            .await
            .unwrap()
            .is_none()
    );
    complete_reset(&db, &env, &challenge, true, 9)
        .await
        .unwrap();
    complete_reset(&db, &env, &challenge, true, 9)
        .await
        .unwrap();
    let payloads: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT payload FROM outbox_messages WHERE consumer=$1 AND idempotency_key=$2",
    )
    .bind(PASSWORD_RESET_COMPLETION_CONSUMER)
    .bind(challenge.id.to_string())
    .fetch_all(db.owner_pool())
    .await
    .unwrap();
    assert_eq!(
        payloads,
        vec![serde_json::json!({"challenge_id": challenge.id.to_string()})]
    );
    let (first, second) = tokio::join!(
        notices.claim_completion_notice(&env, &challenge.id),
        notices.claim_completion_notice(&env, &challenge.id),
    );
    let claims: Vec<_> = [first.unwrap(), second.unwrap()]
        .into_iter()
        .flatten()
        .collect();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].subject, subject);
    assert!(claims[0].recipient.is_some());
    notices
        .record_completion_notice(&env, &challenge.id, PasswordResetDelivery::Accepted, 1)
        .await
        .unwrap();
    assert!(
        notices
            .record_completion_notice(&env, &challenge.id, PasswordResetDelivery::Uncertain, 0)
            .await
            .is_err()
    );
    assert!(
        notices
            .claim_completion_notice(&env, &challenge.id)
            .await
            .unwrap()
            .is_none()
    );
    let status = scoped
        .password_reset()
        .completion_notice_status(&challenge.id)
        .await
        .unwrap()
        .unwrap();
    assert!(status.started_at_unix_micros.is_some());
    assert_eq!(status.result, Some(PasswordResetDelivery::Accepted));
}

#[tokio::test]
async fn completion_notice_enqueue_failure_rolls_back_password_and_case() {
    use ironauth_store::PasswordResetOutcome;
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (subject, recovery, challenge) = reset_fixture(&db, &env, scope).await;
    let store = db.store();
    let scoped = store.scoped(scope);
    let audits_before = scoped.audit().list().await.unwrap().len();
    sqlx::raw_sql("CREATE FUNCTION reject_completion_queue() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.consumer='password-reset-completion' THEN RAISE EXCEPTION 'fixture queue failure'; END IF; RETURN NEW; END $$;
        CREATE TRIGGER reject_completion_queue BEFORE INSERT ON outbox_messages FOR EACH ROW EXECUTE FUNCTION reject_completion_queue();")
        .execute(db.owner_pool()).await.unwrap();
    assert!(
        complete_reset(&db, &env, &challenge, true, 9)
            .await
            .is_err()
    );
    assert_eq!(
        scoped
            .users()
            .password_hash_for_subject(&subject)
            .await
            .unwrap()
            .as_deref(),
        Some(HASH)
    );
    assert_eq!(scoped.audit().list().await.unwrap().len(), audits_before);
    let completed: bool =
        sqlx::query_scalar("SELECT state='completed' FROM recovery_flows WHERE id=$1")
            .bind(recovery.to_string())
            .fetch_one(db.owner_pool())
            .await
            .unwrap();
    assert!(!completed);
    let pending: bool = sqlx::query_scalar(
        "SELECT state='pending' AND attempt_count=0 FROM password_reset_challenges WHERE id=$1",
    )
    .bind(challenge.id.to_string())
    .fetch_one(db.owner_pool())
    .await
    .unwrap();
    assert!(pending);
    sqlx::raw_sql("DROP TRIGGER reject_completion_queue ON outbox_messages; DROP FUNCTION reject_completion_queue();")
        .execute(db.owner_pool()).await.unwrap();
    assert!(matches!(
        complete_reset(&db, &env, &challenge, true, 9)
            .await
            .unwrap(),
        PasswordResetOutcome::Completed { .. }
    ));
}
