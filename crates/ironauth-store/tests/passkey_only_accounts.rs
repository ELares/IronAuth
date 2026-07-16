// SPDX-License-Identifier: MIT OR Apache-2.0

//! Passkey-only (passwordless) accounts and bidirectional password conversion at the
//! store layer (issue #66, PR C), against a real database.
//!
//! These pin the storage-side guarantees the passkey-only lifecycle depends on:
//!
//! - a passwordless signup creates a first-class passkey-only account: the unusable
//!   password sentinel, `passwordless = true`, and the stable WebAuthn user handle
//!   minted at INSERT to the subject id (no non-sentinel `password_hash` ever exists);
//! - that handle is IMMUTABLE (the trigger refuses a change; the app role has no grant),
//!   and `webauthn_credentials.subject` is immutable too (omitted from the update grant);
//! - password -> passkey-only removal is BLOCKED by the cross-source last-credential
//!   guard unless the subject retains a usable passkey, and ALLOWED once one exists;
//! - passkey-only -> password sets the first password only while the account is
//!   passwordless (the sentinel guard never clobbers an existing password).

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, FirstPasswordOutcome, NewWebauthnCredential, PasswordRemovalOutcome, Scope,
    UserId,
};
use sqlx::Row;

/// The unusable password sentinel a passkey-only (or credential-less) account stores in
/// `password_hash`: it can never verify, so no login path can authenticate on it.
const UNUSABLE_SENTINEL: &str = "!";
/// A well-formed Argon2id verifier used where a real password hash is needed.
const REAL_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2g";

async fn register_password_user(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    handle: &str,
) -> UserId {
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .users()
        .register(env, handle, REAL_HASH)
        .await
        .expect("register password user")
}

/// Create a passkey-only account with a pre-allocated id (as the signup ceremony does).
async fn register_passwordless(db: &TestDatabase, env: &Env, scope: Scope, handle: &str) -> UserId {
    let id = UserId::generate(env, &scope);
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .users()
        .register_passwordless(env, &id, handle)
        .await
        .expect("register passwordless user")
}

async fn register_passkey(db: &TestDatabase, env: &Env, scope: Scope, subject: &UserId, id: &[u8]) {
    let transports = vec!["internal".to_string()];
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .webauthn_credentials()
        .register(
            env,
            subject,
            &NewWebauthnCredential {
                credential_id: id,
                cose_public_key: b"cose-key-bytes",
                sign_count: 0,
                aaguid: &[0xAB; 16],
                transports: &transports,
                backup_eligible: true,
                backup_state: true,
                discoverable: Some(true),
                nickname: "phone",
                attestation_type: "none",
                attestation_verified: false,
                attestation_fmt: "none",
            },
        )
        .await
        .expect("register passkey");
}

/// Read the raw `(password_hash, passwordless, webauthn_user_handle)` row as the owner.
async fn read_user_row(db: &TestDatabase, subject: &UserId) -> (String, bool, Option<Vec<u8>>) {
    let row = sqlx::query(
        "SELECT password_hash, passwordless, webauthn_user_handle FROM users WHERE id = $1",
    )
    .bind(subject.to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("read user row");
    (
        row.get("password_hash"),
        row.get("passwordless"),
        row.get("webauthn_user_handle"),
    )
}

#[tokio::test]
async fn passwordless_signup_creates_a_passkey_only_account_with_no_password_row() {
    let env = Env::system();
    let db = TestDatabase::start().await;
    let scope = db.seed_scope(&env).await;
    let subject = register_passwordless(&db, &env, scope, "passkey-only@example.test").await;

    let (password_hash, passwordless, handle) = read_user_row(&db, &subject).await;
    // The account is passkey-only by construction: the sentinel hash (never a real
    // verifier), the passwordless marker, and the handle minted at INSERT to the id bytes.
    assert_eq!(
        password_hash, UNUSABLE_SENTINEL,
        "a passkey-only account never holds a usable password hash"
    );
    assert!(passwordless, "the passwordless marker is set");
    assert_eq!(
        handle.as_deref(),
        Some(subject.to_string().as_bytes()),
        "the stable WebAuthn user handle is the subject id bytes, minted at INSERT"
    );

    // The authoritative marker reads back true; a password account reads false.
    let is_pl = db
        .store()
        .scoped(scope)
        .users()
        .is_passwordless(&subject)
        .await
        .expect("is_passwordless");
    assert_eq!(is_pl, Some(true));
}

#[tokio::test]
async fn a_passkey_only_handle_and_a_credential_subject_are_immutable() {
    let env = Env::system();
    let db = TestDatabase::start().await;
    let scope = db.seed_scope(&env).await;
    let subject = register_passwordless(&db, &env, scope, "immutable@example.test").await;
    register_passkey(&db, &env, scope, &subject, b"cred-immutable").await;

    // The handle was set at INSERT, so even the OWNER cannot change it: the trigger fires.
    let changed = sqlx::query("UPDATE users SET webauthn_user_handle = $1 WHERE id = $2")
        .bind(vec![0xCD_u8; 16])
        .bind(subject.to_string())
        .execute(db.owner_pool())
        .await;
    let error = changed.expect_err("mutating a passkey-only account's handle must be refused");
    assert!(
        error.to_string().contains("immutable"),
        "the immutability trigger must fire, got: {error}"
    );

    // The low-privilege app role has NO grant to name the handle column at all.
    let denied = sqlx::query("UPDATE users SET webauthn_user_handle = $1 WHERE id = $2")
        .bind(vec![0xEF_u8; 16])
        .bind(subject.to_string())
        .execute(db.app_pool())
        .await;
    assert!(
        denied.is_err(),
        "the app role must have no privilege to update webauthn_user_handle"
    );

    // webauthn_credentials.subject is immutable too: it is omitted from the update grant,
    // so a raw UPDATE as the app role (the Kratos-class credential-reassignment attack) is
    // refused at the privilege layer.
    let reassign = sqlx::query("UPDATE webauthn_credentials SET subject = $1 WHERE subject = $2")
        .bind("usr_attacker")
        .bind(subject.to_string())
        .execute(db.app_pool())
        .await;
    assert!(
        reassign.is_err(),
        "the app role must have no privilege to reassign a credential's subject"
    );
}

#[tokio::test]
async fn password_removal_is_blocked_without_a_passkey_and_allowed_with_one() {
    let env = Env::system();
    let db = TestDatabase::start().await;
    let scope = db.seed_scope(&env).await;
    let subject = register_password_user(&db, &env, scope, "convert@example.test").await;

    let acting = || {
        db.store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
    };

    // With no other login factor, removing the password is BLOCKED (self-lockout guard).
    let blocked = acting()
        .users()
        .remove_password(&env, &subject, None, "step_up_max_age_secs=300")
        .await
        .expect("remove_password");
    assert_eq!(blocked, PasswordRemovalOutcome::BlockedLastCredential);
    // Nothing changed: still a password account.
    let (hash, passwordless, _) = read_user_row(&db, &subject).await;
    assert_ne!(
        hash, UNUSABLE_SENTINEL,
        "the password survived the blocked removal"
    );
    assert!(!passwordless);

    // Enroll a passkey, then the removal is ALLOWED (the subject retains a login factor).
    register_passkey(&db, &env, scope, &subject, b"cred-convert").await;
    let removed = acting()
        .users()
        .remove_password(&env, &subject, None, "step_up_max_age_secs=300")
        .await
        .expect("remove_password");
    assert!(matches!(removed, PasswordRemovalOutcome::Removed(_)));
    let (hash, passwordless, _) = read_user_row(&db, &subject).await;
    assert_eq!(hash, UNUSABLE_SENTINEL, "the account is now passkey-only");
    assert!(passwordless);

    // A second removal is the uniform not-found: there is no usable password to remove.
    let again = acting()
        .users()
        .remove_password(&env, &subject, None, "step_up_max_age_secs=300")
        .await
        .expect("remove_password");
    assert_eq!(again, PasswordRemovalOutcome::NotFound);
}

#[tokio::test]
async fn setting_a_first_password_converts_a_passkey_only_account_once() {
    let env = Env::system();
    let db = TestDatabase::start().await;
    let scope = db.seed_scope(&env).await;
    let subject = register_passwordless(&db, &env, scope, "topassword@example.test").await;

    let acting = || {
        db.store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
    };

    // The first password is set: the account flips to password-holding.
    let set = acting()
        .users()
        .set_first_password(&env, &subject, REAL_HASH, None, "step_up_max_age_secs=300")
        .await
        .expect("set_first_password");
    assert!(matches!(set, FirstPasswordOutcome::Set(_)));
    let (hash, passwordless, _) = read_user_row(&db, &subject).await;
    assert_eq!(hash, REAL_HASH, "the first password is stored");
    assert!(!passwordless, "the account is no longer passwordless");

    // A second set is Ineligible: the sentinel guard never clobbers an existing password.
    let again = acting()
        .users()
        .set_first_password(
            &env,
            &subject,
            "$argon2id$v=19$m=19456,t=2,p=1$b3RoZXJzYWx0$b3RoZXJoYXNo",
            None,
            "step_up_max_age_secs=300",
        )
        .await
        .expect("set_first_password");
    assert_eq!(again, FirstPasswordOutcome::Ineligible);
    let (hash, _, _) = read_user_row(&db, &subject).await;
    assert_eq!(hash, REAL_HASH, "the existing password was not clobbered");
}
