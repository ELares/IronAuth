// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end login and rehash per source, against a real database (`DATABASE_URL`).
//!
//! Pins the acceptance-critical criterion of issue #57: a fixture user from each
//! source imports through its front-end AND the #55 streaming engine, then logs in
//! with the ORIGINAL password (verified against the imported foreign hash) and is
//! rehashed to native Argon2id, exactly as the login handler does on first success.
//! This is the credential-intactness proof for Keycloak PBKDF2, Auth0 bcrypt, the
//! Firebase modified scrypt, and the LDAP PBKDF2 scheme.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use ironauth_env::Env;
use ironauth_import::{ImportContext, RecordOutcome, import_stream};
use ironauth_importers::firebase::FirebaseHashParams;
use ironauth_importers::{Mapping, auth0, firebase, keycloak, ldap};
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{CorrelationId, Scope, UserRecord};

/// A fresh native Argon2id verifier for `password`, the rehash target the login
/// handler writes on a successful foreign verify.
fn argon2_hash(password: &str) -> String {
    let salt = SaltString::encode_b64(b"argon2-rehash-salt").expect("salt");
    argon2::Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("argon2 hash")
        .to_string()
}

fn native_verify(record: &UserRecord, password: &str) -> bool {
    match PasswordHash::new(&record.password_hash) {
        Ok(parsed) => argon2::Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// Run a mapping's record lines through the #55 engine into the scope.
async fn import(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    mapping: &Mapping,
) -> Vec<RecordOutcome> {
    let ctx = ImportContext {
        store: db.store(),
        scope,
        env,
        actor: db.test_actor(env),
    };
    let lines = mapping.record_lines().expect("record lines");
    let mut outcomes = Vec::new();
    import_stream(&ctx, lines, |o| outcomes.push(o)).await;
    outcomes
}

/// The shared acceptance flow: import one source's fixture, then prove the fixture
/// user logs in with `password` against the imported foreign hash and rehashes to
/// Argon2id.
async fn assert_login_and_rehash(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    mapping: &Mapping,
    identifier: &str,
    password: &str,
    expected_algo: &str,
) {
    let outcomes = import(db, env, scope, mapping).await;
    assert!(
        outcomes
            .iter()
            .any(|o| matches!(o, RecordOutcome::Created { .. })),
        "at least one user was created"
    );

    // FIRST login: the foreign hash is what authenticates; the native verifier is
    // the unusable import sentinel.
    let record = db
        .store()
        .scoped(scope)
        .users()
        .by_identifier(identifier)
        .await
        .expect("lookup")
        .expect("user exists");
    assert!(
        !native_verify(&record, password),
        "native verifier is the unusable sentinel before first login"
    );
    assert_eq!(record.foreign_password_algo.as_deref(), Some(expected_algo));
    let foreign = record
        .foreign_password_hash
        .as_deref()
        .expect("foreign hash present");
    assert!(
        ironauth_import::ForeignHash::parse(foreign)
            .expect("parse foreign")
            .verify(password.as_bytes()),
        "the original {expected_algo} password verifies against the imported foreign hash"
    );

    // The verify-then-rehash landing: write a fresh native Argon2id verifier and
    // retire the foreign hash.
    let native = argon2_hash(password);
    let upgraded = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .users()
        .upgrade_foreign_password(env, &record.id, &native)
        .await
        .expect("upgrade");
    assert!(upgraded, "the first upgrade flips the row");

    // SECOND login: Argon2id only, foreign hash gone.
    let record2 = db
        .store()
        .scoped(scope)
        .users()
        .by_identifier(identifier)
        .await
        .expect("lookup")
        .expect("exists");
    assert!(
        record2.foreign_password_hash.is_none(),
        "foreign hash retired"
    );
    assert!(
        native_verify(&record2, password),
        "Argon2id verifies after rehash"
    );
}

#[tokio::test]
async fn keycloak_user_logs_in_and_rehashes() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x57_01);
    let scope = db.seed_scope(&env).await;
    let mapping =
        keycloak::map_realm(include_str!("fixtures/keycloak_realm.json")).expect("map keycloak");
    assert_login_and_rehash(
        &db,
        &env,
        scope,
        &mapping,
        "alice",
        "keycloak-pw-1",
        "pbkdf2",
    )
    .await;
}

#[tokio::test]
async fn auth0_user_logs_in_and_rehashes() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x57_02);
    let scope = db.seed_scope(&env).await;
    let mapping = auth0::map_export(
        include_str!("fixtures/auth0_users.json"),
        Some(include_str!("fixtures/auth0_password_hashes.ndjson")),
    )
    .expect("map auth0");
    assert_login_and_rehash(
        &db,
        &env,
        scope,
        &mapping,
        "carol@acme.test",
        "auth0-pw-1",
        "bcrypt",
    )
    .await;
}

#[tokio::test]
async fn firebase_user_logs_in_and_rehashes() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x57_03);
    let scope = db.seed_scope(&env).await;
    let params =
        FirebaseHashParams::from_hash_config(include_str!("fixtures/firebase_hash_config.json"))
            .expect("hash config");
    let mapping =
        firebase::map_export(include_str!("fixtures/firebase_export.json"), &params).expect("map");
    assert_login_and_rehash(
        &db,
        &env,
        scope,
        &mapping,
        "frank@acme.test",
        "user1password",
        "firebase-scrypt",
    )
    .await;
}

#[tokio::test]
async fn ldap_user_logs_in_and_rehashes() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x57_04);
    let scope = db.seed_scope(&env).await;
    let mapping = ldap::map_entries(include_str!("fixtures/ldap_entries.json")).expect("map ldap");
    assert_login_and_rehash(&db, &env, scope, &mapping, "judy", "ldap-pw-1", "pbkdf2").await;
}
