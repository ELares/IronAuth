// SPDX-License-Identifier: MIT OR Apache-2.0

//! Self-service account management at the store layer (issue #61), against a real
//! database.
//!
//! These pin the store-side guarantees the end-user account surface is built on:
//!
//! - a password change WRITES the new Argon2id verifier and, in the SAME
//!   transaction (session-fixation defense), revokes every OTHER session of the
//!   user while KEEPING the one the change is made from;
//! - the credential registry round-trips (enroll / list / remove) with the
//!   user-authored friendly name SEALED at rest (a raw column probe yields no
//!   plaintext) and decrypted back only through the master key;
//! - the last-usable-credential GUARDRAIL blocks removing a user's last
//!   primary-login credential unless the recovery acknowledgment is present;
//! - a credential id belonging to ANOTHER subject is the uniform not-found, never
//!   actionable (the anti-IDOR contract, within a tenant);
//! - every mutation is audited to the acting principal.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    Action, CorrelationId, CredentialRemoveOutcome, CredentialType, NewSession, Scope, SessionId,
    UserId,
};
use sqlx::Row;

/// A far-future expiry (year 2100) in epoch microseconds, so a session that stops
/// resolving can only have stopped because it was revoked, never because it expired.
const FAR_FUTURE_MICROS: i64 = 4_102_444_800_000_000;

/// Register a bootstrap user with a placeholder hash and return its subject id.
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

/// Create a live session for `subject`, rotating away `prior` if given.
async fn create_session(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    subject: &str,
    prior: Option<&SessionId>,
) -> SessionId {
    let id = SessionId::generate(env, &scope);
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .sessions()
        .rotate(
            env,
            &id,
            prior,
            NewSession {
                subject,
                auth_methods: "pwd",
                auth_time_micros: 0,
                idle_expires_micros: FAR_FUTURE_MICROS,
                absolute_expires_micros: FAR_FUTURE_MICROS,
                user_agent: None,
                peer_ip: None,
            },
        )
        .await
        .expect("rotate session");
    id
}

#[tokio::test]
async fn password_change_writes_the_new_hash_and_revokes_other_sessions_keeping_the_current_one() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = register_user(&db, &env, scope, "ada@example.test").await;
    let subject_text = subject.to_string();

    // The user is signed in on three devices; the change is made from `current`.
    let current = create_session(&db, &env, scope, &subject_text, None).await;
    let other_a = create_session(&db, &env, scope, &subject_text, None).await;
    let other_b = create_session(&db, &env, scope, &subject_text, None).await;

    let new_hash = "$argon2id$v=19$m=19456,t=2,p=1$bmV3c2FsdG5ldw$bmV3aGFzaG5ldw";
    let outcome = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .users()
        .change_password(
            &env,
            &subject,
            new_hash,
            Some(&current),
            "step_up_max_age_secs=300",
        )
        .await
        .expect("change password");

    // The two OTHER sessions were revoked; the current one was kept.
    assert_eq!(outcome.sessions_revoked, 2, "both other sessions revoked");
    let read = db.store().scoped(scope).sessions();
    assert!(
        read.get(&current, 0, 0).await.expect("read").is_some(),
        "the session the change was made from survives"
    );
    for stale in [&other_a, &other_b] {
        assert!(
            read.get(stale, 0, 0).await.expect("read").is_none(),
            "a stale session stops resolving immediately after the password change"
        );
    }

    // The stored verifier is the new one (never the old one).
    let stored = db
        .store()
        .scoped(scope)
        .users()
        .password_hash_for_subject(&subject)
        .await
        .expect("read hash")
        .expect("user exists");
    assert_eq!(stored, new_hash, "the new verifier is stored");

    // The change is audited against the user.
    let rows = db
        .store()
        .scoped(scope)
        .audit()
        .list()
        .await
        .expect("list audit");
    let changes = rows
        .iter()
        .filter(|row| {
            row.action == Action::AccountPasswordChange.as_str() && row.target_id == subject_text
        })
        .count();
    assert_eq!(changes, 1, "exactly one password-change audit row");
}

#[tokio::test]
async fn credential_enroll_list_remove_round_trips_with_the_friendly_name_sealed() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = register_user(&db, &env, scope, "grace@example.test").await;

    let acting = db.store();
    let id = acting
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .account_credentials()
        .enroll(
            &env,
            &subject,
            CredentialType::Passkey,
            "my work laptop",
            "step_up_max_age_secs=300",
        )
        .await
        .expect("enroll credential");

    // The list returns the credential with its decrypted friendly name.
    let listed = db
        .store()
        .scoped(scope)
        .account_credentials()
        .list(&subject, 50, None)
        .await
        .expect("list credentials");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, id.to_string());
    assert_eq!(listed[0].friendly_name, "my work laptop");
    assert_eq!(listed[0].credential_type, "passkey");
    assert!(listed[0].usable_for_login, "a passkey is a primary factor");

    // The friendly name is SEALED at rest: a raw column probe (as the owner,
    // bypassing row-level security) yields no plaintext.
    let raw: Vec<u8> =
        sqlx::query("SELECT friendly_name_sealed FROM account_credentials WHERE id = $1")
            .bind(id.to_string())
            .fetch_one(db.owner_pool())
            .await
            .expect("raw probe")
            .get("friendly_name_sealed");
    assert!(
        !String::from_utf8_lossy(&raw).contains("my work laptop"),
        "the friendly name must never appear in plaintext at rest"
    );

    // Remove it (with the recovery acknowledgment, since it is the last usable one).
    let outcome = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .account_credentials()
        .remove(&env, &subject, &id, true, "step_up_max_age_secs=300")
        .await
        .expect("remove credential");
    assert_eq!(outcome, CredentialRemoveOutcome::Removed);
    let after = db
        .store()
        .scoped(scope)
        .account_credentials()
        .list(&subject, 50, None)
        .await
        .expect("list after remove");
    assert!(after.is_empty(), "the credential is gone");
}

#[tokio::test]
async fn last_usable_credential_guardrail_blocks_removal_without_acknowledgment() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = register_user(&db, &env, scope, "hedy@example.test").await;

    let enroll = |name: &'static str, kind: CredentialType| {
        let db = &db;
        let env = &env;
        async move {
            db.store()
                .scoped(scope)
                .acting(db.test_actor(env), CorrelationId::generate(env))
                .account_credentials()
                .enroll(env, &subject, kind, name, "step_up_max_age_secs=300")
                .await
                .expect("enroll")
        }
    };

    let passkey = enroll("only passkey", CredentialType::Passkey).await;
    // A TOTP is NOT a primary login factor, so it does not rescue the guardrail.
    let _totp = enroll("phone totp", CredentialType::Totp).await;

    // Removing the LAST primary-login credential without acknowledgment is blocked.
    let blocked = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .account_credentials()
        .remove(&env, &subject, &passkey, false, "step_up_max_age_secs=300")
        .await
        .expect("remove attempt");
    assert_eq!(
        blocked,
        CredentialRemoveOutcome::BlockedLastCredential,
        "the last primary-login credential cannot be removed silently"
    );
    // The credential is still there (nothing was removed).
    assert_eq!(
        db.store()
            .scoped(scope)
            .account_credentials()
            .list(&subject, 50, None)
            .await
            .expect("list")
            .len(),
        2,
        "a blocked removal changes nothing"
    );

    // Enrolling a SECOND passkey makes the first no longer the last usable one.
    let second = enroll("backup passkey", CredentialType::Passkey).await;
    let removed = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .account_credentials()
        .remove(&env, &subject, &passkey, false, "step_up_max_age_secs=300")
        .await
        .expect("remove");
    assert_eq!(
        removed,
        CredentialRemoveOutcome::Removed,
        "a non-last primary-login credential removes without acknowledgment"
    );

    // With the recovery acknowledgment the last one CAN be removed.
    let acknowledged = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .account_credentials()
        .remove(&env, &subject, &second, true, "step_up_max_age_secs=300")
        .await
        .expect("remove with ack");
    assert_eq!(acknowledged, CredentialRemoveOutcome::Removed);
}

#[tokio::test]
async fn a_credential_of_another_subject_is_the_uniform_not_found() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let victim = register_user(&db, &env, scope, "victim@example.test").await;
    let attacker = register_user(&db, &env, scope, "attacker@example.test").await;

    // The victim enrolls a credential.
    let victim_credential = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .account_credentials()
        .enroll(
            &env,
            &victim,
            CredentialType::Passkey,
            "victim laptop",
            "step_up_max_age_secs=300",
        )
        .await
        .expect("enroll");

    // The attacker (same tenant, DIFFERENT subject) tries to remove it: uniform
    // not-found, and the victim's credential is untouched.
    let outcome = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .account_credentials()
        .remove(
            &env,
            &attacker,
            &victim_credential,
            true,
            "step_up_max_age_secs=300",
        )
        .await
        .expect("remove attempt");
    assert_eq!(
        outcome,
        CredentialRemoveOutcome::NotFound,
        "a cross-subject credential id is never actionable"
    );
    assert_eq!(
        db.store()
            .scoped(scope)
            .account_credentials()
            .list(&victim, 50, None)
            .await
            .expect("list")
            .len(),
        1,
        "the victim's credential survives the cross-subject removal attempt"
    );
    // The attacker cannot even SEE it in their own list.
    assert!(
        db.store()
            .scoped(scope)
            .account_credentials()
            .list(&attacker, 50, None)
            .await
            .expect("list")
            .is_empty(),
        "the attacker's own credential list never includes the victim's"
    );
}
