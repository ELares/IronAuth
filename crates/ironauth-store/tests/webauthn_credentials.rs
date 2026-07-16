// SPDX-License-Identifier: MIT OR Apache-2.0

//! WebAuthn passkey persistence at the store layer (issue #65), against a real
//! database.
//!
//! These pin the store-side guarantees the ceremony endpoints depend on:
//!
//! - a verified registration round-trips (register / list / find-for-assertion)
//!   with the COSE public key stored verbatim and the nickname SEALED at rest;
//! - the excludeCredentials dedupe is enforced at the DATABASE: the same
//!   credential id cannot be registered twice (a `Conflict`);
//! - an assertion advances the signature counter and updates the backup state;
//! - a sign-count regression sets the clone-detected flag AND writes a
//!   `webauthn.clone.detected` audit row, while a normal assertion writes none;
//! - a challenge is single-use: consuming it twice, past its expiry, or for the
//!   wrong ceremony fails;
//! - a credential belonging to ANOTHER subject is the uniform not-found.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    Action, CorrelationId, CredentialRemoveOutcome, NewWebauthnCredential, Scope, UserId,
    WEBAUTHN_CHALLENGE_TTL_SECS, WebauthnCeremony, WebauthnChallengeId, WebauthnCredentialId,
};
use sqlx::Row;

async fn register_user(db: &TestDatabase, env: &Env, scope: Scope, handle: &str) -> UserId {
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .users()
        .register(
            env,
            handle,
            "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2g",
        )
        .await
        .expect("register user")
}

fn new_credential<'a>(
    credential_id: &'a [u8],
    cose: &'a [u8],
    transports: &'a [String],
    nickname: &'a str,
) -> NewWebauthnCredential<'a> {
    NewWebauthnCredential {
        credential_id,
        cose_public_key: cose,
        sign_count: 0,
        aaguid: &[0xAB; 16],
        transports,
        backup_eligible: true,
        backup_state: true,
        discoverable: Some(true),
        nickname,
    }
}

#[tokio::test]
async fn register_list_and_find_round_trip_with_the_nickname_sealed() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = register_user(&db, &env, scope, "alice@example.test").await;

    let transports = vec!["internal".to_string(), "hybrid".to_string()];
    let id = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .webauthn_credentials()
        .register(
            &env,
            &subject,
            &new_credential(b"cred-id-1", b"cose-key-bytes", &transports, "my phone"),
        )
        .await
        .expect("register passkey");

    // List returns the credential with its metadata and decrypted nickname.
    let listed = db
        .store()
        .scoped(scope)
        .webauthn_credentials()
        .list(&subject, 10, None)
        .await
        .expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, id.to_string());
    assert_eq!(listed[0].credential_id, b"cred-id-1");
    assert_eq!(listed[0].cose_public_key, b"cose-key-bytes");
    assert_eq!(listed[0].nickname, "my phone");
    assert!(listed[0].backup_eligible);
    assert!(listed[0].backup_state);
    assert_eq!(listed[0].discoverable, Some(true));
    assert_eq!(listed[0].transports, vec!["internal", "hybrid"]);

    // The nickname is SEALED at rest: a raw owner probe yields no plaintext.
    let raw: Vec<u8> =
        sqlx::query("SELECT nickname_sealed FROM webauthn_credentials WHERE id = $1")
            .bind(id.to_string())
            .fetch_one(db.owner_pool())
            .await
            .expect("raw probe")
            .get("nickname_sealed");
    assert!(!String::from_utf8_lossy(&raw).contains("my phone"));

    // find_for_assertion resolves the credential by its raw credential id.
    let target = db
        .store()
        .scoped(scope)
        .webauthn_credentials()
        .find_for_assertion(b"cred-id-1")
        .await
        .expect("find")
        .expect("present");
    assert_eq!(target.id, id.to_string());
    assert_eq!(target.subject, subject.to_string());
    assert_eq!(target.cose_public_key, b"cose-key-bytes");
    assert_eq!(target.sign_count, 0);

    // The descriptors for excludeCredentials list the credential id.
    let descriptors = db
        .store()
        .scoped(scope)
        .webauthn_credentials()
        .descriptors(&subject)
        .await
        .expect("descriptors");
    assert_eq!(descriptors.len(), 1);
    assert_eq!(descriptors[0].credential_id, b"cred-id-1");
}

#[tokio::test]
async fn a_duplicate_credential_id_is_refused_the_database_dedupe() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = register_user(&db, &env, scope, "bob@example.test").await;
    let transports: Vec<String> = vec![];

    let repo = || {
        db.store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
    };
    repo()
        .webauthn_credentials()
        .register(
            &env,
            &subject,
            &new_credential(b"dup-cred", b"cose-a", &transports, "first"),
        )
        .await
        .expect("first register");

    // The SAME credential id, even a fresh ceremony, is rejected as a Conflict.
    let err = repo()
        .webauthn_credentials()
        .register(
            &env,
            &subject,
            &new_credential(b"dup-cred", b"cose-b", &transports, "second"),
        )
        .await
        .expect_err("duplicate refused");
    assert!(matches!(err, ironauth_store::StoreError::Conflict));
}

#[tokio::test]
async fn an_assertion_advances_the_counter_and_a_regression_flags_a_clone_with_an_audit() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = register_user(&db, &env, scope, "carol@example.test").await;
    let transports: Vec<String> = vec![];

    let id = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .webauthn_credentials()
        .register(
            &env,
            &subject,
            &NewWebauthnCredential {
                sign_count: 0,
                ..new_credential(b"counter-cred", b"cose", &transports, "key")
            },
        )
        .await
        .expect("register");

    // A normal assertion advances the counter and updates backup state; no audit.
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .webauthn_credentials()
        .record_assertion(&env, &id, 5, false, false, "policy: warn")
        .await
        .expect("record normal assertion");
    let (count, backup, clone): (i64, bool, bool) = {
        let row = sqlx::query(
            "SELECT sign_count, backup_state, clone_detected FROM webauthn_credentials WHERE id = $1",
        )
        .bind(id.to_string())
        .fetch_one(db.owner_pool())
        .await
        .unwrap();
        (
            row.get("sign_count"),
            row.get("backup_state"),
            row.get("clone_detected"),
        )
    };
    assert_eq!(count, 5);
    assert!(!backup);
    assert!(!clone);
    assert_eq!(
        clone_events(&db, &id).await,
        0,
        "no clone event on a normal assertion"
    );

    // A regressing counter flags the clone AND writes a clone-detected audit row,
    // and does NOT advance the stored counter.
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .webauthn_credentials()
        .record_assertion(&env, &id, 3, true, true, "policy: block")
        .await
        .expect("record regressed assertion");
    let (count2, clone2): (i64, bool) = {
        let row = sqlx::query(
            "SELECT sign_count, clone_detected FROM webauthn_credentials WHERE id = $1",
        )
        .bind(id.to_string())
        .fetch_one(db.owner_pool())
        .await
        .unwrap();
        (row.get("sign_count"), row.get("clone_detected"))
    };
    assert_eq!(count2, 5, "a regressed counter is not stored");
    assert!(clone2, "the clone flag is set");
    assert_eq!(
        clone_events(&db, &id).await,
        1,
        "one clone-detected audit row"
    );
}

async fn clone_events(db: &TestDatabase, id: &WebauthnCredentialId) -> i64 {
    sqlx::query("SELECT count(*) AS n FROM audit_log WHERE action = $1 AND target_id = $2")
        .bind(Action::WebauthnCloneDetected.as_str())
        .bind(id.to_string())
        .fetch_one(db.owner_pool())
        .await
        .unwrap()
        .get("n")
}

#[tokio::test]
async fn a_challenge_is_single_use() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = register_user(&db, &env, scope, "dave@example.test").await;

    let issued = db
        .store()
        .scoped(scope)
        .webauthn_challenges()
        .issue(
            &env,
            WebauthnCeremony::Register,
            Some(&subject),
            WEBAUTHN_CHALLENGE_TTL_SECS,
        )
        .await
        .expect("issue");
    assert_eq!(issued.challenge.len(), 32);
    let handle = WebauthnChallengeId::parse_in_scope(&issued.id, &scope).expect("parse handle");

    // First consume succeeds and returns the challenge + bound subject.
    let consumed = db
        .store()
        .scoped(scope)
        .webauthn_challenges()
        .consume(&env, &handle, WebauthnCeremony::Register)
        .await
        .expect("consume")
        .expect("present");
    assert_eq!(consumed.challenge, issued.challenge);
    assert_eq!(
        consumed.subject.as_deref(),
        Some(subject.to_string().as_str())
    );

    // Second consume of the same handle fails (single use).
    let again = db
        .store()
        .scoped(scope)
        .webauthn_challenges()
        .consume(&env, &handle, WebauthnCeremony::Register)
        .await
        .expect("second consume");
    assert!(
        again.is_none(),
        "a consumed challenge cannot be redeemed again"
    );
}

#[tokio::test]
async fn a_challenge_for_the_wrong_ceremony_is_refused() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let issued = db
        .store()
        .scoped(scope)
        .webauthn_challenges()
        .issue(
            &env,
            WebauthnCeremony::Authenticate,
            None,
            WEBAUTHN_CHALLENGE_TTL_SECS,
        )
        .await
        .expect("issue");
    let handle = WebauthnChallengeId::parse_in_scope(&issued.id, &scope).expect("parse");
    // Consuming an authentication challenge as a registration challenge fails.
    let wrong = db
        .store()
        .scoped(scope)
        .webauthn_challenges()
        .consume(&env, &handle, WebauthnCeremony::Register)
        .await
        .expect("consume");
    assert!(wrong.is_none());
}

#[tokio::test]
async fn another_subjects_credential_is_the_uniform_not_found_on_remove() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let owner = register_user(&db, &env, scope, "owner@example.test").await;
    let other = register_user(&db, &env, scope, "other@example.test").await;
    let transports: Vec<String> = vec![];

    let id = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .webauthn_credentials()
        .register(
            &env,
            &owner,
            &new_credential(b"owned", b"cose", &transports, "owner key"),
        )
        .await
        .expect("register");

    // The other subject cannot remove the owner's credential.
    let outcome = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .webauthn_credentials()
        .remove(&env, &other, &id, false)
        .await
        .expect("remove");
    assert_eq!(outcome, CredentialRemoveOutcome::NotFound);

    // The owner can (they hold a password, so the passkey is not their last usable
    // login factor), and it is audited.
    let outcome = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .webauthn_credentials()
        .remove(&env, &owner, &id, false)
        .await
        .expect("remove");
    assert_eq!(outcome, CredentialRemoveOutcome::Removed);
}

/// Register a PASSWORDLESS user: the native `password_hash` is the unusable sentinel
/// (`!`), exactly as a passkey-invitation activation leaves it, so a passkey is the
/// user's only login factor.
async fn register_passwordless_user(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    handle: &str,
) -> UserId {
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .users()
        .register(env, handle, "!")
        .await
        .expect("register passwordless user")
}

#[tokio::test]
async fn a_passwordless_user_cannot_remove_their_last_passkey_without_acknowledgment() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = register_passwordless_user(&db, &env, scope, "solo@example.test").await;
    let transports: Vec<String> = vec![];

    let id = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .webauthn_credentials()
        .register(
            &env,
            &subject,
            &new_credential(b"only", b"cose", &transports, "only key"),
        )
        .await
        .expect("register");

    // Removing the last usable login factor with NO acknowledgment is blocked, and
    // the credential is untouched (a blocked removal deletes nothing).
    let blocked = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .webauthn_credentials()
        .remove(&env, &subject, &id, false)
        .await
        .expect("remove");
    assert_eq!(blocked, CredentialRemoveOutcome::BlockedLastCredential);
    let still_there = db
        .store()
        .scoped(scope)
        .webauthn_credentials()
        .list(&subject, 10, None)
        .await
        .expect("list");
    assert_eq!(still_there.len(), 1, "a blocked removal deletes nothing");

    // With the recovery acknowledgment, the removal proceeds.
    let removed = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .webauthn_credentials()
        .remove(&env, &subject, &id, true)
        .await
        .expect("remove");
    assert_eq!(removed, CredentialRemoveOutcome::Removed);
}

#[tokio::test]
async fn a_passkey_that_is_not_the_last_login_factor_removes_without_acknowledgment() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let transports: Vec<String> = vec![];

    // A passwordless user with TWO passkeys: removing the first (the second remains a
    // usable factor) is allowed without acknowledgment; removing the now-last one is
    // then blocked.
    let subject = register_passwordless_user(&db, &env, scope, "pair@example.test").await;
    let first = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .webauthn_credentials()
        .register(
            &env,
            &subject,
            &new_credential(b"first", b"cose", &transports, "first key"),
        )
        .await
        .expect("register first");
    let second = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .webauthn_credentials()
        .register(
            &env,
            &subject,
            &new_credential(b"second", b"cose", &transports, "second key"),
        )
        .await
        .expect("register second");
    let removed = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .webauthn_credentials()
        .remove(&env, &subject, &first, false)
        .await
        .expect("remove first");
    assert_eq!(
        removed,
        CredentialRemoveOutcome::Removed,
        "not the last factor: removable without acknowledgment"
    );
    let blocked = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .webauthn_credentials()
        .remove(&env, &subject, &second, false)
        .await
        .expect("remove second");
    assert_eq!(
        blocked,
        CredentialRemoveOutcome::BlockedLastCredential,
        "the now-last passkey is protected"
    );

    // A user who HOLDS a native password can remove a lone passkey freely: the
    // password is the remaining login factor.
    let with_pw = register_user(&db, &env, scope, "haspw@example.test").await;
    let pk = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .webauthn_credentials()
        .register(
            &env,
            &with_pw,
            &new_credential(b"pwpk", b"cose", &transports, "pw user key"),
        )
        .await
        .expect("register");
    let removed = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .webauthn_credentials()
        .remove(&env, &with_pw, &pk, false)
        .await
        .expect("remove");
    assert_eq!(
        removed,
        CredentialRemoveOutcome::Removed,
        "a native password is a remaining login factor"
    );
}
