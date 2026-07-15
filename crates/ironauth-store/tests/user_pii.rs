// SPDX-License-Identifier: MIT OR Apache-2.0

//! The bootstrap `users` PII columns are sealed at rest (issue #48), over a real
//! database (`DATABASE_URL`).
//!
//! Proves the acceptance criteria at the persistence layer for the two classified
//! PII columns the login/consent bootstrap shipped: the login handle (`identifier`)
//! and the standard-claim document (`claims`). A registered user's plaintext handle
//! and claims never land in a column (a database dump reveals neither), the handle
//! is still equality-searchable through its blind index (login works), the claims
//! round-trip exactly, and neither the sealed values nor the blind index leak
//! across tenants.

use ironauth_store::test_support::TestDatabase;
use ironauth_store::{CorrelationId, Scope, StoreError};
use sqlx::Row;

const PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaGhhc2hoYXNo";

/// Register a user with claims in `scope`, returning its subject (the user id).
async fn register(
    db: &TestDatabase,
    env: &ironauth_env::Env,
    scope: Scope,
    identifier: &str,
    claims_json: &str,
) -> String {
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .users()
        .register_with_claims(env, identifier, PASSWORD_HASH, claims_json)
        .await
        .expect("register user")
        .to_string()
}

/// The raw stored PII columns for a user, read as the superuser owner (bypassing
/// row-level security): the "database dump" a stolen backup would expose.
async fn dump_user(db: &TestDatabase, scope: Scope, subject: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let row = sqlx::query(
        "SELECT identifier_bidx, identifier_sealed, claims_sealed FROM users \
         WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
    )
    .bind(subject)
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("dump user row");
    (
        row.get::<Vec<u8>, _>("identifier_bidx"),
        row.get::<Vec<u8>, _>("identifier_sealed"),
        row.get::<Vec<u8>, _>("claims_sealed"),
    )
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test]
async fn a_database_dump_of_users_carries_no_plaintext_identifier_or_claims() {
    let db = TestDatabase::start().await;
    let (env, _clock) = ironauth_env::Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x48);
    let scope = db.seed_scope(&env).await;

    let identifier = "ada.lovelace@example.test";
    let claims = r#"{"email":"ada.lovelace@example.test","name":"Ada Lovelace"}"#;
    let subject = register(&db, &env, scope, identifier, claims).await;

    // What an operator or a stolen backup sees: the sealed columns must contain
    // neither the handle nor the claim values verbatim. (Against the pre-fix schema
    // these were plaintext `identifier` / `claims` text columns, so this assertion
    // would FAIL; it passes only because 0027 sealed them.)
    let (bidx, id_sealed, claims_sealed) = dump_user(&db, scope, &subject).await;
    assert!(
        !contains(&id_sealed, identifier.as_bytes()),
        "the sealed identifier must not contain the plaintext handle"
    );
    assert!(
        !contains(&claims_sealed, b"ada.lovelace@example.test"),
        "the sealed claims must not contain the plaintext email"
    );
    assert!(
        !contains(&claims_sealed, b"Ada Lovelace"),
        "the sealed claims must not contain the plaintext name"
    );
    // The blind index is a one-way HMAC, not the handle: it must not contain the
    // plaintext either.
    assert!(
        !contains(&bidx, identifier.as_bytes()),
        "the blind index must not contain the plaintext handle"
    );
    assert_eq!(bidx.len(), 32, "the blind index is a full HMAC-SHA256 tag");
}

#[tokio::test]
async fn login_lookup_by_identifier_works_through_the_blind_index() {
    let db = TestDatabase::start().await;
    let (env, _clock) = ironauth_env::Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x49);
    let scope = db.seed_scope(&env).await;

    let identifier = "grace@example.test";
    let subject = register(&db, &env, scope, identifier, "{}").await;

    // The login surface resolves a user BY identifier; it must still find the row
    // (the equality lookup queries the blind index) and recover the plaintext handle
    // and the password hash for verification.
    let found = db
        .store()
        .scoped(scope)
        .users()
        .by_identifier(identifier)
        .await
        .expect("lookup ok")
        .expect("user is found by identifier through the blind index");
    assert_eq!(found.id.to_string(), subject);
    assert_eq!(
        found.identifier, identifier,
        "the handle round-trips on read"
    );
    assert_eq!(found.password_hash, PASSWORD_HASH);

    // A different handle in the same scope is a clean miss (not an error).
    assert!(
        db.store()
            .scoped(scope)
            .users()
            .by_identifier("nobody@example.test")
            .await
            .expect("lookup ok")
            .is_none()
    );
}

#[tokio::test]
async fn claims_round_trip_exactly_on_read() {
    let db = TestDatabase::start().await;
    let (env, _clock) = ironauth_env::Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x4a);
    let scope = db.seed_scope(&env).await;

    let claims = r#"{"email":"eve@example.test","email_verified":true,"name":"Eve"}"#;
    let subject = register(&db, &env, scope, "eve@example.test", claims).await;

    let read = db
        .store()
        .scoped(scope)
        .users()
        .claims_for_subject(&subject)
        .await
        .expect("read claims ok")
        .expect("the user has a claim document");
    assert_eq!(
        read, claims,
        "the sealed claims decrypt to the exact plaintext"
    );
}

#[tokio::test]
async fn a_duplicate_identifier_in_scope_is_a_conflict() {
    let db = TestDatabase::start().await;
    let (env, _clock) = ironauth_env::Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x4b);
    let scope = db.seed_scope(&env).await;

    register(&db, &env, scope, "dup@example.test", "{}").await;
    let second = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .users()
        .register_with_claims(&env, "dup@example.test", PASSWORD_HASH, "{}")
        .await;
    // The blind-index unique constraint rejects the duplicate handle exactly as the
    // old plaintext UNIQUE did.
    assert!(
        matches!(second, Err(StoreError::Conflict)),
        "a duplicate handle is a conflict, got: {second:?}"
    );
}

#[tokio::test]
async fn the_same_identifier_in_two_tenants_neither_collides_nor_leaks() {
    let db = TestDatabase::start().await;
    let (env, _clock) = ironauth_env::Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x4c);
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;

    // The SAME login handle and claims registered independently in two tenants.
    let shared = "shared@example.test";
    let claims = r#"{"email":"shared@example.test"}"#;
    let subject_a = register(&db, &env, scope_a, shared, claims).await;
    let subject_b = register(&db, &env, scope_b, shared, claims).await;
    assert_ne!(subject_a, subject_b);

    let (bidx_a, id_sealed_a, claims_sealed_a) = dump_user(&db, scope_a, &subject_a).await;
    let (bidx_b, id_sealed_b, claims_sealed_b) = dump_user(&db, scope_b, &subject_b).await;

    // The blind index is per-tenant keyed: the same handle maps to DIFFERENT tags,
    // so an index collision cannot leak the handle across tenants.
    assert_ne!(
        bidx_a, bidx_b,
        "the per-tenant blind index of the same handle differs across tenants"
    );
    // The sealed ciphertext also differs (fresh nonce + tenant-bound AAD).
    assert_ne!(id_sealed_a, id_sealed_b);
    assert_ne!(claims_sealed_a, claims_sealed_b);

    // Each tenant resolves ONLY its own user by the shared handle: tenant B's lookup
    // returns B's subject, never A's (row-level security plus the per-tenant blind
    // index), so a shared handle never crosses the tenant boundary.
    let b_lookup = db
        .store()
        .scoped(scope_b)
        .users()
        .by_identifier(shared)
        .await
        .expect("lookup ok")
        .expect("B finds its own user");
    assert_eq!(b_lookup.id.to_string(), subject_b);
    assert_ne!(b_lookup.id.to_string(), subject_a);
}
