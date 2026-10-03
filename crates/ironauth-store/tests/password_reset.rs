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
          subject,identifier_id,recipient_revision,recovery_id,credential_digest,code_hash,created_at,expires_at) \
         VALUES ($1,$2,$3,'fixture-client',decode(repeat('ab',32),'hex'),'/authorize?fixture=1',\
          $4,$5,$6,$7,$8,'fixture-hash',TIMESTAMPTZ '2026-10-03 00:00:00Z',\
          TIMESTAMPTZ '2026-10-03 00:05:00Z')",
    )
    .bind(id.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(bound.then_some("fixture-subject"))
    .bind(bound.then_some("fixture-identifier"))
    .bind(bound.then_some("fixture-revision"))
    .bind(bound.then_some("fixture-recovery"))
    .bind(bound.then_some(vec![1_u8; 32]))
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
        "attempt_count=-1",
        "expires_at=created_at",
        "expires_at=created_at+interval '11 minutes'",
        "browser_binding_hash=decode('ab','hex')",
        "identifier_id=NULL",
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
    let error = sqlx::query("UPDATE password_reset_challenges SET state='completed',attempt_count=1,finished_at=created_at+interval '1 minute',completion_request_hash=decode(repeat('ab',32),'hex'),completion_credential_digest=decode(repeat('cd',32),'hex') WHERE id=$1")
        .bind(decoy.to_string()).execute(db.owner_pool()).await.expect_err("decoy cannot become completed authority");
    assert_eq!(sqlstate(&error).as_deref(), Some("23514"));
    sqlx::query("UPDATE password_reset_challenges SET state='completed',attempt_count=1,finished_at=created_at+interval '1 minute',completion_request_hash=decode(repeat('ab',32),'hex'),completion_credential_digest=decode(repeat('cd',32),'hex') WHERE id=$1")
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

async fn verified_account(db: &TestDatabase, env: &Env, scope: Scope) -> ironauth_store::UserId {
    use ironauth_store::{CorrelationId, NewRecipientChallenge, RecipientAttempt};
    let store = db.store();
    let acting = store
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env));
    let subject = acting
        .users()
        .register(env, EMAIL, HASH, None)
        .await
        .unwrap();
    let id = RecipientChallengeId::generate(env, &scope);
    acting
        .recipient_verification()
        .start(
            env,
            NewRecipientChallenge {
                id: &id,
                subject: &subject,
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
        .challenge(env, &subject, &id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        acting
            .recipient_verification()
            .attempt(env, &subject, &challenge, true)
            .await
            .unwrap(),
        RecipientAttempt::Verified
    );
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

async fn reset_fixture(
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
    use ironauth_store::{
        CorrelationId, NewRefreshFamily, NewTrustedDevice, PasswordResetOutcome, RefreshFamilyId,
        RefreshTokenId, refresh_token_digest,
    };
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (subject, _, challenge) = reset_fixture(&db, &env, scope).await;
    let session = reset_session(&db, &env, &subject).await;
    let grant = reset_offline_grant(&db, &env, scope, &subject.to_string(), Some(&session)).await;
    let store = db.store();
    let scoped = store.scoped(scope);
    let acting = scoped.acting(db.test_actor(&env), CorrelationId::generate(&env));
    let family = RefreshFamilyId::generate(&env, &scope);
    let token = RefreshTokenId::generate(&env, &scope);
    acting
        .refresh()
        .issue(
            &env,
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
                created_at_unix_micros: now_micros(&env),
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
            &env,
            &subject,
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
    assert!(
        scoped
            .trusted_devices()
            .validate(&device, &subject, &[5; 32], now_micros(&env))
            .await
            .unwrap()
            .is_some()
    );
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
    let row = sqlx::query("SELECT f.revoked_at IS NOT NULL AS family_revoked,g.revoked_at IS NOT NULL AS grant_revoked FROM refresh_families f JOIN grants g ON g.id=f.grant_id WHERE f.id=$1")
        .bind(family.to_string()).fetch_one(db.owner_pool()).await.unwrap();
    assert!(row.get::<bool, _>("family_revoked"));
    assert!(row.get::<bool, _>("grant_revoked"));
    let events = scoped.session_events().pending(100).await.unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].session_id, session.to_string());
    assert_eq!(
        events[0].cause,
        ironauth_store::SessionEndCause::PasswordChanged
    );
}
