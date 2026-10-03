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
    // Reissue needs a scoped DELETE, but the application cannot erase another
    // environment's challenge even when it knows the exact row ID.
    let before: String = sqlx::query_scalar(
        "SELECT row_to_json(c)::text FROM recipient_verification_challenges c WHERE id = $1",
    )
    .bind(id.to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("owned preimage");
    let mut tx = db
        .app_pool()
        .begin()
        .await
        .expect("foreign app transaction");
    sqlx::query("SELECT set_config('ironauth.tenant_id', $1, true), set_config('ironauth.environment_id', $2, true)")
        .bind(foreign.tenant().to_string()).bind(foreign.environment().to_string()).execute(&mut *tx).await.expect("foreign scope");
    let denied = sqlx::query("DELETE FROM recipient_verification_challenges WHERE id = $1")
        .bind(id.to_string())
        .execute(&mut *tx)
        .await
        .expect("RLS filters delete");
    assert_eq!(denied.rows_affected(), 0);
    tx.commit()
        .await
        .expect("foreign attempt committed with no effect");
    let after: String = sqlx::query_scalar(
        "SELECT row_to_json(c)::text FROM recipient_verification_challenges c WHERE id = $1",
    )
    .bind(id.to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("owned postimage");
    assert_eq!(before, after);
    assert!(
        verified(&db, &owner, EMAIL).await,
        "foreign delete preserves current proof"
    );
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

#[tokio::test]
async fn reissue_replaces_an_active_challenge_and_keeps_one_row_per_subject() {
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH + Duration::from_secs(1000), 1438);
    let scope = db.seed_scope(&env).await;
    let owner = signup(&db, &env, scope, EMAIL).await;
    let first = issue(&db, &env, &owner, EMAIL).await.expect("first start");
    let old_code = challenge(&db, &env, &owner, &first).await;
    clock.advance(Duration::from_secs(61));
    let second = issue(&db, &env, &owner, EMAIL)
        .await
        .expect("active reissue");
    assert_ne!(first, second);
    let rows: Vec<String> = sqlx::query_scalar("SELECT id FROM recipient_verification_challenges WHERE tenant_id = $1 AND environment_id = $2 AND subject = $3")
        .bind(scope.tenant().to_string()).bind(scope.environment().to_string()).bind(owner.to_string())
        .fetch_all(db.owner_pool()).await.expect("bounded challenge rows");
    assert_eq!(rows, vec![second.to_string()]);
    assert!(matches!(
        attempt(&db, &env, &owner, &old_code, true).await,
        Err(StoreError::NotFound)
    ));
    let current = challenge(&db, &env, &owner, &second).await;
    assert_eq!(
        attempt(&db, &env, &owner, &current, true)
            .await
            .expect("current code verifies"),
        RecipientAttempt::Verified
    );
    assert_eq!(
        audit_count(&db).await,
        3,
        "two starts and exactly one committed verification"
    );
}

async fn make_legacy(db: &TestDatabase, scope: Scope) {
    sqlx::query("UPDATE users SET recipient_email_indexed = false, recipient_email_bidx = NULL WHERE tenant_id = $1 AND environment_id = $2")
        .bind(scope.tenant().to_string()).bind(scope.environment().to_string())
        .execute(db.owner_pool()).await.expect("simulate pre-index retained rows");
}

async fn backfill(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    limit: u32,
) -> Result<ironauth_store::RecipientIndexReport, StoreError> {
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .recipient_verification()
        .index_backfill(env, limit, None)
        .await
}

async fn retained_account_data(db: &TestDatabase, scope: Scope) -> Vec<serde_json::Value> {
    sqlx::query_scalar("SELECT to_jsonb(u) - 'recipient_email_indexed' - 'recipient_email_bidx' FROM users u WHERE tenant_id = $1 AND environment_id = $2 ORDER BY id")
        .bind(scope.tenant().to_string()).bind(scope.environment().to_string())
        .fetch_all(db.owner_pool()).await.expect("retained encrypted account data")
}

#[tokio::test]
async fn legacy_index_batches_preserve_every_other_account_column_and_never_verify() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let foreign = db.seed_scope(&env).await;
    let owner = signup(&db, &env, scope, EMAIL).await;
    let retired = signup(&db, &env, scope, "retired@example.test").await;
    signup(&db, &env, foreign, "foreign@example.test").await;
    sqlx::query("UPDATE users SET deleted_at = now() WHERE id = $1")
        .bind(retired.to_string())
        .execute(db.owner_pool())
        .await
        .expect("retained deleted fixture");
    make_legacy(&db, scope).await;
    make_legacy(&db, foreign).await;
    let before = retained_account_data(&db, scope).await;
    let foreign_before = retained_account_data(&db, foreign).await;
    let preview = db
        .control_store()
        .scoped(scope)
        .recipient_verification()
        .index_preview(1)
        .await
        .expect("preview");
    assert!(!preview.applied);
    assert_eq!(
        (
            preview.total_users,
            preview.unindexed_users,
            preview.batch_users
        ),
        (2, 2, 1)
    );
    assert_eq!(audit_count(&db).await, 0);
    let first = backfill(&db, &env, scope, 1).await.expect("first batch");
    assert!(first.applied);
    assert!(!first.index_complete);
    assert_eq!(first.unindexed_users, 1);
    let last = backfill(&db, &env, scope, 1)
        .await
        .expect("last batch includes deleted user");
    assert!(last.index_complete);
    assert_eq!(last.ambiguous_indexed_mailboxes, 0);
    let empty = backfill(&db, &env, scope, 1)
        .await
        .expect("complete is repeatable");
    assert_eq!(empty.batch_users, 0);
    assert_eq!(retained_account_data(&db, scope).await, before);
    assert_eq!(retained_account_data(&db, foreign).await, foreign_before);
    let untouched = db
        .control_store()
        .scoped(foreign)
        .recipient_verification()
        .index_preview(100)
        .await
        .expect("foreign preview");
    assert_eq!(untouched.unindexed_users, 1);
    assert!(
        !verified(&db, &owner, EMAIL).await,
        "indexing is not verification"
    );
    assert_eq!(audit_count(&db).await, 3);
    assert!(
        issue(&db, &env, &owner, EMAIL).await.is_ok(),
        "indexed unique owner can begin the real ceremony"
    );
    for limit in [0, 101, u32::MAX] {
        assert!(matches!(
            backfill(&db, &env, scope, limit).await,
            Err(StoreError::Invalid)
        ));
    }
}

#[tokio::test]
async fn legacy_index_reports_unicode_primary_and_foreign_typed_ambiguity_without_merging() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let owner = signup(&db, &env, scope, EMAIL).await;
    signup(&db, &env, scope, "Ｏwner@example.test").await;
    let other = signup(&db, &env, scope, "other@example.test").await;
    add_typed(&db, &env, &other, "OWNER@example.test", false).await;
    make_legacy(&db, scope).await;
    let before = retained_account_data(&db, scope).await;
    let report = backfill(&db, &env, scope, 100)
        .await
        .expect("index ambiguous rows");
    assert!(
        report.index_complete,
        "complete metadata does not promise unambiguous ownership"
    );
    assert_eq!(report.total_users, 3);
    assert_eq!(report.ambiguous_indexed_mailboxes, 1);
    assert_eq!(retained_account_data(&db, scope).await, before);
    assert!(!verified(&db, &owner, EMAIL).await);
    assert!(matches!(
        issue(&db, &env, &owner, EMAIL).await,
        Err(StoreError::NotFound)
    ));
}

#[tokio::test]
async fn unreadable_legacy_identifier_rolls_back_batch_and_audit_and_runtime_cannot_write_indices()
{
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let owner = signup(&db, &env, scope, EMAIL).await;
    signup(&db, &env, scope, "another@example.test").await;
    make_legacy(&db, scope).await;
    let denied = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .recipient_verification()
        .index_backfill(&env, 100, None)
        .await;
    match denied {
        Err(StoreError::Database(error)) => assert_eq!(
            error.as_database_error().and_then(|e| e.code()).as_deref(),
            Some("42501")
        ),
        other => panic!("runtime role must receive SQL permission denial: {other:?}"),
    }
    let sealed: Vec<u8> = sqlx::query_scalar("SELECT identifier_sealed FROM users WHERE id = $1")
        .bind(owner.to_string())
        .fetch_one(db.owner_pool())
        .await
        .expect("sealed fixture");
    sqlx::query("UPDATE users SET identifier_sealed = $2 WHERE id = $1")
        .bind(owner.to_string())
        .bind(vec![0_u8; 50])
        .execute(db.owner_pool())
        .await
        .expect("corrupt ciphertext fixture");
    assert!(backfill(&db, &env, scope, 100).await.is_err());
    assert!(
        db.control_store()
            .scoped(scope)
            .recipient_verification()
            .index_preview(100)
            .await
            .is_err()
    );
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM users WHERE NOT recipient_email_indexed")
            .fetch_one(db.owner_pool())
            .await
            .expect("unchanged index count");
    assert_eq!(remaining, 2);
    assert_eq!(audit_count(&db).await, 0);
    sqlx::query("UPDATE users SET identifier_sealed = $2 WHERE id = $1")
        .bind(owner.to_string())
        .bind(sealed)
        .execute(db.owner_pool())
        .await
        .expect("repair fixture only");
    assert!(
        backfill(&db, &env, scope, 100)
            .await
            .expect("retry after repair")
            .index_complete
    );
}
