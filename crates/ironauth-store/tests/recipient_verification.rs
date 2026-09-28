// SPDX-License-Identifier: MIT OR Apache-2.0

//! Subject-bound recipient verification over real isolated Postgres (issue #1436).
//! The fixture drives normal password signup, not an invented pre-verified identity.

use std::time::{Duration, SystemTime};

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, IdentifierType, NewRecipientChallenge, NewUserIdentifier, RecipientAttempt,
    RecipientChallenge, RecipientChallengeId, Scope, StoreError, UniquenessMode, UserId,
    UserIdentifierId,
};
use sqlx::Row;

const HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaGhhc2hoYXNo";
const EMAIL: &str = "Owner@Example.test";

fn now(env: &Env) -> i64 {
    i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("after epoch")
            .as_micros(),
    )
    .expect("fits")
}

async fn signup(db: &TestDatabase, env: &Env, scope: Scope, email: &str) -> UserId {
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .users()
        .register(env, email, HASH, None)
        .await
        .expect("ordinary password signup")
}

async fn issue(
    db: &TestDatabase,
    env: &Env,
    subject: &UserId,
    email: &str,
) -> Result<RecipientChallengeId, StoreError> {
    let id = RecipientChallengeId::generate(env, &subject.scope());
    let recipient = db
        .store()
        .scoped(subject.scope())
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .recipient_verification()
        .start(
            env,
            NewRecipientChallenge {
                id: &id,
                subject,
                email,
                code_hash: HASH,
                expires_at_unix_micros: now(env) + 300_000_000,
            },
        )
        .await?;
    assert_eq!(
        recipient, EMAIL,
        "transport gets the stored primary spelling"
    );
    Ok(id)
}

async fn challenge(
    db: &TestDatabase,
    env: &Env,
    user: &UserId,
    id: &RecipientChallengeId,
) -> RecipientChallenge {
    db.store()
        .scoped(user.scope())
        .recipient_verification()
        .challenge(env, user, id)
        .await
        .expect("challenge read")
        .expect("active challenge")
}

async fn attempt(
    db: &TestDatabase,
    env: &Env,
    user: &UserId,
    code: &RecipientChallenge,
    matched: bool,
) -> Result<RecipientAttempt, StoreError> {
    db.store()
        .scoped(user.scope())
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .recipient_verification()
        .attempt(env, user, code, matched)
        .await
}

async fn verified(db: &TestDatabase, user: &UserId, email: &str) -> bool {
    db.store()
        .scoped(user.scope())
        .recipient_verification()
        .current(user, email)
        .await
        .expect("current proof read")
        .is_some()
}

async fn add_typed(
    db: &TestDatabase,
    env: &Env,
    subject: &UserId,
    raw: &str,
    verified: bool,
) -> UserIdentifierId {
    let scope = subject.scope();
    let id = UserIdentifierId::generate(env, &scope);
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .user_identifiers()
        .add(
            env,
            NewUserIdentifier {
                id: &id,
                user_id: subject,
                identifier_type: IdentifierType::Email,
                raw,
                verified,
                mode: UniquenessMode::NonUnique,
                org: None,
            },
            None,
        )
        .await
        .expect("typed fixture identifier");
    id
}

async fn audit_count(db: &TestDatabase) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE action LIKE 'recipient_verification.%'",
    )
    .fetch_one(db.owner_pool())
    .await
    .expect("audit count")
}

#[tokio::test]
async fn password_signup_verifies_its_own_stored_mailbox_without_changing_login_state() {
    let db = TestDatabase::start().await;
    let (env, _) = Env::deterministic(SystemTime::UNIX_EPOCH + Duration::from_secs(1000), 1436);
    let scope = db.seed_scope(&env).await;
    let user = signup(&db, &env, scope, EMAIL).await;
    let before: (String, String, Vec<u8>) =
        sqlx::query_as("SELECT state, password_hash, claims_sealed FROM users WHERE id = $1")
            .bind(user.to_string())
            .fetch_one(db.owner_pool())
            .await
            .expect("before account");
    assert!(!verified(&db, &user, EMAIL).await);
    let id = issue(&db, &env, &user, "owner@example.test")
        .await
        .expect("start");
    assert!(!verified(&db, &user, EMAIL).await);
    let code = challenge(&db, &env, &user, &id).await;
    assert_eq!(
        attempt(&db, &env, &user, &code, true)
            .await
            .expect("commit"),
        RecipientAttempt::Verified
    );
    let proof = db
        .store()
        .scoped(scope)
        .recipient_verification()
        .current(&user, "Ｏwner@example.test")
        .await
        .expect("canonical equality")
        .expect("verified owner");
    assert_eq!(proof.revision, id);
    assert_eq!(proof.verified_at_unix_micros, now(&env));
    assert!(!verified(&db, &user, "other@example.test").await);
    assert!(matches!(
        attempt(&db, &env, &user, &code, true).await,
        Err(StoreError::NotFound)
    ));
    let after: (String, String, Vec<u8>) =
        sqlx::query_as("SELECT state, password_hash, claims_sealed FROM users WHERE id = $1")
            .bind(user.to_string())
            .fetch_one(db.owner_pool())
            .await
            .expect("after account");
    assert_eq!(before, after);
    let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions")
        .fetch_one(db.owner_pool())
        .await
        .expect("sessions");
    assert_eq!(sessions, 0, "verification cannot create a session");
    assert_eq!(audit_count(&db).await, 2);
    let stored: ValueRow =
        sqlx::query_as("SELECT row_to_json(c)::text FROM recipient_verification_challenges c")
            .fetch_one(db.owner_pool())
            .await
            .expect("challenge at rest");
    assert!(
        !stored.0.contains(EMAIL),
        "no plaintext mailbox in challenge"
    );
    assert!(
        stored.0.contains(HASH),
        "only the one-way verifier is persisted"
    );
}

type ValueRow = (String,);

#[tokio::test]
async fn scope_subject_and_primary_ownership_are_not_caller_selectable() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let other_scope = db.seed_scope(&env).await;
    let owner = signup(&db, &env, scope, EMAIL).await;
    let wrong = signup(&db, &env, scope, "wrong@example.test").await;
    let foreign = signup(&db, &env, other_scope, EMAIL).await;
    let id = issue(&db, &env, &owner, EMAIL).await.expect("owner start");
    let code = challenge(&db, &env, &owner, &id).await;
    assert!(matches!(
        issue(&db, &env, &wrong, EMAIL).await,
        Err(StoreError::NotFound)
    ));
    for subject in [&wrong, &foreign] {
        assert!(
            db.store()
                .scoped(subject.scope())
                .recipient_verification()
                .challenge(&env, subject, &id)
                .await
                .expect("lookup")
                .is_none()
        );
        assert!(matches!(
            attempt(&db, &env, subject, &code, true).await,
            Err(StoreError::NotFound)
        ));
        assert!(!verified(&db, subject, EMAIL).await);
    }
    let cross = db
        .store()
        .scoped(other_scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .recipient_verification()
        .start(
            &env,
            NewRecipientChallenge {
                id: &id,
                subject: &owner,
                email: EMAIL,
                code_hash: HASH,
                expires_at_unix_micros: now(&env) + 300_000_000,
            },
        )
        .await;
    assert!(matches!(cross, Err(StoreError::NotFound)));
    assert_eq!(
        audit_count(&db).await,
        1,
        "denials have no recipient mutations/audits"
    );
}

#[tokio::test]
async fn canonical_primary_or_typed_ambiguity_and_legacy_scope_refuse_verification() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    for kind in ["primary", "typed", "legacy", "disabled", "quarantined"] {
        let scope = db.seed_scope(&env).await;
        let owner = signup(&db, &env, scope, EMAIL).await;
        let other = signup(
            &db,
            &env,
            scope,
            if kind == "primary" {
                "owner@example.test"
            } else {
                "other@example.test"
            },
        )
        .await;
        match kind {
            "typed" => {
                add_typed(&db, &env, &other, "Ｏwner@example.test", true).await;
            }
            "legacy" => {
                sqlx::query("UPDATE users SET recipient_email_indexed = false WHERE id = $1")
                    .bind(other.to_string())
                    .execute(db.owner_pool())
                    .await
                    .expect("legacy row");
            }
            "disabled" => {
                sqlx::query("UPDATE users SET state = 'disabled' WHERE id = $1")
                    .bind(owner.to_string())
                    .execute(db.owner_pool())
                    .await
                    .expect("disabled row");
            }
            "quarantined" => {
                sqlx::query("UPDATE users SET quarantined = true WHERE id = $1")
                    .bind(owner.to_string())
                    .execute(db.owner_pool())
                    .await
                    .expect("quarantined row");
            }
            _ => {}
        }
        assert!(
            matches!(
                issue(&db, &env, &owner, EMAIL).await,
                Err(StoreError::NotFound)
            ),
            "{kind}"
        );
        assert!(!verified(&db, &owner, EMAIL).await, "{kind}");
    }
    assert_eq!(audit_count(&db).await, 0);
}

#[tokio::test]
async fn stale_identifier_and_new_ambiguity_are_rechecked_after_challenge_issuance() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    for kind in ["replace", "new_primary", "new_typed", "disable"] {
        let scope = db.seed_scope(&env).await;
        let owner = signup(&db, &env, scope, EMAIL).await;
        let identifier = add_typed(&db, &env, &owner, EMAIL, false).await;
        let id = issue(&db, &env, &owner, EMAIL)
            .await
            .expect("start before change");
        let code = challenge(&db, &env, &owner, &id).await;
        match kind {
            "replace" => {
                db.control_store()
                    .scoped(scope)
                    .acting(db.test_actor(&env), CorrelationId::generate(&env))
                    .user_identifiers()
                    .remove(&env, &owner, &identifier)
                    .await
                    .expect("remove old");
                add_typed(&db, &env, &owner, EMAIL, false).await;
            }
            "new_primary" => {
                signup(&db, &env, scope, "owner@example.test").await;
            }
            "new_typed" => {
                let wrong = signup(&db, &env, scope, "wrong@example.test").await;
                add_typed(&db, &env, &wrong, EMAIL, true).await;
            }
            "disable" => {
                sqlx::query("UPDATE users SET state = 'disabled' WHERE id = $1")
                    .bind(owner.to_string())
                    .execute(db.owner_pool())
                    .await
                    .expect("disable");
            }
            _ => unreachable!(),
        }
        assert!(
            matches!(
                attempt(&db, &env, &owner, &code, true).await,
                Err(StoreError::NotFound)
            ),
            "{kind}"
        );
        assert!(!verified(&db, &owner, EMAIL).await, "{kind}");
    }
    assert_eq!(
        audit_count(&db).await,
        4,
        "only the four accepted challenge starts committed"
    );
}

#[tokio::test]
async fn bounded_attempts_expiry_reissue_and_hash_fencing_are_durable() {
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH + Duration::from_secs(1000), 1437);
    let scope = db.seed_scope(&env).await;
    let owner = signup(&db, &env, scope, EMAIL).await;
    let id = issue(&db, &env, &owner, EMAIL).await.expect("start");
    let code = challenge(&db, &env, &owner, &id).await;
    let changed_hash = RecipientChallenge {
        id,
        code_hash: format!("{HASH}different"),
    };
    assert!(matches!(
        attempt(&db, &env, &owner, &changed_hash, true).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        issue(&db, &env, &owner, EMAIL).await,
        Err(StoreError::QuotaExceeded)
    ));
    for _ in 0..5 {
        assert_eq!(
            attempt(&db, &env, &owner, &code, false)
                .await
                .expect("wrong attempt counted"),
            RecipientAttempt::Refused
        );
    }
    assert!(matches!(
        attempt(&db, &env, &owner, &code, true).await,
        Err(StoreError::NotFound)
    ));
    assert!(!verified(&db, &owner, EMAIL).await);
    clock.advance(Duration::from_secs(61));
    let next = issue(&db, &env, &owner, EMAIL)
        .await
        .expect("new challenge");
    assert_ne!(next, id);
    assert!(matches!(
        attempt(&db, &env, &owner, &code, true).await,
        Err(StoreError::NotFound)
    ));
    let expired = challenge(&db, &env, &owner, &next).await;
    clock.advance(Duration::from_secs(300));
    assert!(matches!(
        attempt(&db, &env, &owner, &expired, true).await,
        Err(StoreError::NotFound)
    ));
    assert!(!verified(&db, &owner, EMAIL).await);
}

#[tokio::test]
async fn one_concurrent_consumer_and_one_atomic_ownership_audit_commit() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let owner = signup(&db, &env, scope, EMAIL).await;
    let id = issue(&db, &env, &owner, EMAIL).await.expect("start");
    let code = challenge(&db, &env, &owner, &id).await;
    let poisoned = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .recipient_verification()
        .attempt_poisoned_for_test(&env, &owner, &code)
        .await;
    assert!(matches!(poisoned, Err(StoreError::Database(_))));
    assert!(!verified(&db, &owner, EMAIL).await);
    assert_eq!(
        audit_count(&db).await,
        1,
        "start only after rolled-back verify"
    );
    assert!(
        db.store()
            .scoped(scope)
            .user_identifiers()
            .list_for_user(&owner)
            .await
            .expect("identifiers")
            .is_empty()
    );
    let (one, two) = tokio::join!(
        attempt(&db, &env, &owner, &code, true),
        attempt(&db, &env, &owner, &code, true)
    );
    assert_eq!(
        usize::from(matches!(one, Ok(RecipientAttempt::Verified)))
            + usize::from(matches!(two, Ok(RecipientAttempt::Verified))),
        1
    );
    assert_eq!(
        usize::from(matches!(one, Err(StoreError::NotFound)))
            + usize::from(matches!(two, Err(StoreError::NotFound))),
        1
    );
    assert!(verified(&db, &owner, EMAIL).await);
    assert_eq!(audit_count(&db).await, 2);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM recipient_email_verifications")
        .fetch_one(db.owner_pool())
        .await
        .expect("verified rows");
    assert_eq!(count, 1);
}

#[tokio::test]
async fn current_proof_does_not_trust_old_verified_flags_or_replaced_identifiers() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let owner = signup(&db, &env, scope, EMAIL).await;
    let prior = add_typed(&db, &env, &owner, EMAIL, true).await;
    assert!(
        !verified(&db, &owner, EMAIL).await,
        "admin/stored flag is not a purpose-bound ceremony"
    );
    let id = issue(&db, &env, &owner, EMAIL).await.expect("start");
    let code = challenge(&db, &env, &owner, &id).await;
    attempt(&db, &env, &owner, &code, true)
        .await
        .expect("verify");
    assert!(verified(&db, &owner, EMAIL).await);
    sqlx::query("UPDATE user_identifiers SET verified = false WHERE id = $1")
        .bind(prior.to_string())
        .execute(db.owner_pool())
        .await
        .expect("unverify");
    assert!(!verified(&db, &owner, EMAIL).await);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .user_identifiers()
        .remove(&env, &owner, &prior)
        .await
        .expect("remove");
    add_typed(&db, &env, &owner, EMAIL, true).await;
    assert!(
        !verified(&db, &owner, EMAIL).await,
        "same label and verified flag cannot revive old row revision"
    );
}

#[tokio::test]
async fn new_relations_force_rls_and_application_grants_do_not_rewrite_authority() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let foreign = db.seed_scope(&env).await;
    let owner = signup(&db, &env, scope, EMAIL).await;
    let id = issue(&db, &env, &owner, EMAIL).await.expect("start");
    let code = challenge(&db, &env, &owner, &id).await;
    attempt(&db, &env, &owner, &code, true)
        .await
        .expect("verify");
    let mut tx = db.app_pool().begin().await.expect("app transaction");
    sqlx::query("SELECT set_config('ironauth.tenant_id', $1, true), set_config('ironauth.environment_id', $2, true)")
        .bind(foreign.tenant().to_string()).bind(foreign.environment().to_string()).execute(&mut *tx).await.expect("foreign scope");
    for table in [
        "recipient_verification_challenges",
        "recipient_email_verifications",
    ] {
        let count: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
            .fetch_one(&mut *tx)
            .await
            .expect("RLS-filtered read");
        assert_eq!(count, 0);
        let flags = sqlx::query(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = $1",
        )
        .bind(table)
        .fetch_one(db.owner_pool())
        .await
        .expect("RLS flags");
        assert!(
            flags.get::<bool, _>("relrowsecurity") && flags.get::<bool, _>("relforcerowsecurity")
        );
    }
    tx.rollback().await.expect("end scope");
    for query in [
        "UPDATE recipient_verification_challenges SET subject = subject",
        "UPDATE recipient_verification_challenges SET code_hash = code_hash",
        "UPDATE recipient_email_verifications SET subject = subject",
        "UPDATE users SET recipient_email_indexed = true",
    ] {
        assert!(
            sqlx::query(query).execute(db.app_pool()).await.is_err(),
            "forbidden authority update: {query}"
        );
    }
}
