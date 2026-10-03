// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reset schema and issuance isolation, not a complete reset ceremony.
//! Schema rows are metadata fixtures; repository cases use actual signup and
//! mailbox verification. No user credential is changed by these tests.

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
