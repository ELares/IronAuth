// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-tenant envelope encryption for PII and secrets (issue #48), over a real
//! database (`DATABASE_URL`).
//!
//! Proves the acceptance criteria at the persistence layer: a secret round-trips
//! through the scoped repository; a ciphertext fails authenticated decryption
//! under another tenant's keys and under a different column context; KEK rotation
//! re-wraps DEKs online with NO payload rewrite (old ciphertext still reads); DEK
//! rotation versions new writes while old versions stay readable, with observable
//! background re-encryption; crypto-shredding a tenant KEK renders that tenant's
//! data permanently unreadable while a sibling tenant is unaffected; and a
//! database dump of the encrypted columns yields no plaintext and nothing
//! replayable across rows or tenants.

use ironauth_env::Env;
use ironauth_jose::MasterKey;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{CorrelationId, Scope, StoreError};
use sqlx::Row;

/// A fresh random platform master key from the entropy seam.
fn master_key(env: &Env) -> MasterKey {
    MasterKey::generate("master-test-1", env.entropy())
}

/// Provision a scope's KEK and DEK so it can seal secrets.
async fn provision(db: &TestDatabase, env: &Env, master: &MasterKey, scope: Scope) {
    let acting = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env));
    acting
        .envelope()
        .provision_kek(env, master)
        .await
        .expect("provision kek");
    acting
        .envelope()
        .provision_dek(env, master)
        .await
        .expect("provision dek");
}

/// Write an encrypted secret under `purpose` in `scope`.
async fn put_secret(
    db: &TestDatabase,
    env: &Env,
    master: &MasterKey,
    scope: Scope,
    purpose: &str,
    plaintext: &[u8],
) {
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .envelope()
        .put_secret(env, master, purpose, plaintext)
        .await
        .expect("put secret");
}

/// The raw stored ciphertext for a scope's secret, read as the superuser owner
/// (which bypasses row-level security): the "database dump" an operator or a
/// stolen backup would see.
async fn dump_ciphertext(db: &TestDatabase, scope: Scope, purpose: &str) -> Vec<u8> {
    sqlx::query(
        "SELECT ciphertext FROM encrypted_secrets \
         WHERE tenant_id = $1 AND environment_id = $2 AND purpose = $3",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(purpose)
    .fetch_one(db.owner_pool())
    .await
    .expect("dump ciphertext")
    .get::<Vec<u8>, _>("ciphertext")
}

#[tokio::test]
async fn secret_round_trips_through_the_scoped_repository() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let master = master_key(&env);
    let scope = db.seed_scope(&env).await;
    provision(&db, &env, &master, scope).await;

    let plaintext = b"ada@lovelace.test";
    put_secret(&db, &env, &master, scope, "email", plaintext).await;

    let opened = db
        .store()
        .scoped(scope)
        .envelope()
        .open_secret(&master, "email")
        .await
        .expect("open secret");
    assert_eq!(opened, plaintext);

    // A missing purpose is a NotFound, distinct from a decryption failure.
    assert!(matches!(
        db.store()
            .scoped(scope)
            .envelope()
            .open_secret(&master, "phone")
            .await,
        Err(StoreError::NotFound)
    ));
}

#[tokio::test]
async fn ciphertext_fails_under_another_tenant_and_another_context() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let master = master_key(&env);

    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    provision(&db, &env, &master, scope_a).await;
    provision(&db, &env, &master, scope_b).await;

    let plaintext = b"cross-tenant-pii";
    put_secret(&db, &env, &master, scope_a, "email", plaintext).await;

    // Tenant B cannot see tenant A's secret at all (scope isolation): a read in B
    // is a uniform NotFound, never a plaintext.
    assert!(matches!(
        db.store()
            .scoped(scope_b)
            .envelope()
            .open_secret(&master, "email")
            .await,
        Err(StoreError::NotFound)
    ));

    // Cross-context replay: lift tenant A's ciphertext and plant it, as the
    // superuser, into tenant B under the SAME purpose, and also into tenant A
    // under a DIFFERENT purpose. Both bind a different AAD context than the blob
    // was sealed under, so both fail authenticated decryption (never plaintext).
    let ciphertext_a = dump_ciphertext(&db, scope_a, "email").await;

    // Same purpose, wrong tenant: give B a DEK version 1 row (it has one) and
    // plant A's ciphertext into a B row under a fresh purpose.
    sqlx::query(
        "INSERT INTO encrypted_secrets (id, tenant_id, environment_id, purpose, dek_version, ciphertext) \
         VALUES ($1, $2, $3, $4, 1, $5)",
    )
    .bind(format!("sec_planted_b_{}", scope_b.tenant()))
    .bind(scope_b.tenant().to_string())
    .bind(scope_b.environment().to_string())
    .bind("email")
    .bind(&ciphertext_a)
    .execute(db.owner_pool())
    .await
    .expect("plant A ciphertext into B");
    assert!(
        matches!(
            db.store()
                .scoped(scope_b)
                .envelope()
                .open_secret(&master, "email")
                .await,
            Err(StoreError::Encryption)
        ),
        "tenant A ciphertext must not decrypt under tenant B's keys"
    );

    // Different column, same tenant: plant A's ciphertext into A under a new
    // purpose. The purpose is bound as AAD, so it fails to authenticate.
    sqlx::query(
        "INSERT INTO encrypted_secrets (id, tenant_id, environment_id, purpose, dek_version, ciphertext) \
         VALUES ($1, $2, $3, $4, 1, $5)",
    )
    .bind(format!("sec_planted_a_{}", scope_a.tenant()))
    .bind(scope_a.tenant().to_string())
    .bind(scope_a.environment().to_string())
    .bind("phone")
    .bind(&ciphertext_a)
    .execute(db.owner_pool())
    .await
    .expect("plant A ciphertext under a different column");
    assert!(
        matches!(
            db.store()
                .scoped(scope_a)
                .envelope()
                .open_secret(&master, "phone")
                .await,
            Err(StoreError::Encryption)
        ),
        "a ciphertext must not decrypt under a different column context"
    );
}

#[tokio::test]
async fn database_dump_yields_no_plaintext_and_nothing_replayable() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let master = master_key(&env);

    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    provision(&db, &env, &master, scope_a).await;
    provision(&db, &env, &master, scope_b).await;

    // The SAME plaintext in two tenants.
    let plaintext = b"identical-secret-material";
    put_secret(&db, &env, &master, scope_a, "email", plaintext).await;
    put_secret(&db, &env, &master, scope_b, "email", plaintext).await;

    let dump_a = dump_ciphertext(&db, scope_a, "email").await;
    let dump_b = dump_ciphertext(&db, scope_b, "email").await;

    // The dump contains no plaintext.
    for dump in [&dump_a, &dump_b] {
        assert!(
            !dump.windows(plaintext.len()).any(|w| w == plaintext),
            "the stored ciphertext must not contain the plaintext"
        );
    }
    // Identical plaintext seals to distinct ciphertext across tenants (distinct
    // keys and nonces), so nothing is replayable or correlatable across rows.
    assert_ne!(
        dump_a, dump_b,
        "identical plaintext must not yield identical ciphertext"
    );
}

#[tokio::test]
async fn kek_rotation_rewraps_deks_without_reencrypting_payloads() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let master = master_key(&env);
    let scope = db.seed_scope(&env).await;
    provision(&db, &env, &master, scope).await;

    let plaintext = b"survives-kek-rotation";
    put_secret(&db, &env, &master, scope, "email", plaintext).await;
    let before = dump_ciphertext(&db, scope, "email").await;

    // Rotate the KEK online.
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .envelope()
        .rotate_kek(&env, &master)
        .await
        .expect("rotate kek");

    // The active KEK advanced to version 2; the DEK stayed version 1 but now
    // points at KEK version 2 (a cheap re-wrap).
    assert_eq!(
        db.store()
            .scoped(scope)
            .envelope()
            .active_kek_version()
            .await
            .unwrap(),
        Some(2)
    );
    let dek_kek_version: i32 = sqlx::query(
        "SELECT kek_version FROM tenant_deks WHERE tenant_id = $1 AND environment_id = $2 AND version = 1",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("read dek")
    .get("kek_version");
    assert_eq!(
        dek_kek_version, 2,
        "the DEK was re-wrapped under the new KEK"
    );

    // The record payload was NOT rewritten: the stored ciphertext is byte-identical.
    let after = dump_ciphertext(&db, scope, "email").await;
    assert_eq!(before, after, "KEK rotation must not rewrite the payload");

    // The secret still reads, now through the rotated KEK.
    let opened = db
        .store()
        .scoped(scope)
        .envelope()
        .open_secret(&master, "email")
        .await
        .expect("open after kek rotation");
    assert_eq!(opened, plaintext);
}

#[tokio::test]
async fn dek_rotation_versions_new_writes_and_reencryption_is_observable() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let master = master_key(&env);
    let scope = db.seed_scope(&env).await;
    provision(&db, &env, &master, scope).await;

    // A secret written under DEK version 1.
    let old_plaintext = b"written-under-dek-v1";
    put_secret(&db, &env, &master, scope, "email", old_plaintext).await;
    assert_eq!(
        db.store()
            .scoped(scope)
            .envelope()
            .secret_dek_version("email")
            .await
            .unwrap(),
        1
    );

    // Rotate the DEK: new writes use version 2, old rows stay readable.
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .envelope()
        .rotate_dek(&env, &master)
        .await
        .expect("rotate dek");
    assert_eq!(
        db.store()
            .scoped(scope)
            .envelope()
            .active_dek_version()
            .await
            .unwrap(),
        Some(2)
    );

    // A NEW secret is sealed under version 2.
    let new_plaintext = b"written-under-dek-v2";
    put_secret(&db, &env, &master, scope, "phone", new_plaintext).await;
    assert_eq!(
        db.store()
            .scoped(scope)
            .envelope()
            .secret_dek_version("phone")
            .await
            .unwrap(),
        2
    );

    // The OLD secret is still on version 1 and still readable throughout.
    assert_eq!(
        db.store()
            .scoped(scope)
            .envelope()
            .secret_dek_version("email")
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        db.store()
            .scoped(scope)
            .envelope()
            .open_secret(&master, "email")
            .await
            .unwrap(),
        old_plaintext
    );

    // Background re-encryption advances the old row to the active version, and is
    // observable through its DEK version. The plaintext is unchanged.
    let advanced = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .envelope()
        .reencrypt_secret(&env, &master, "email")
        .await
        .expect("reencrypt");
    assert!(advanced, "the old-version secret was re-encrypted");
    assert_eq!(
        db.store()
            .scoped(scope)
            .envelope()
            .secret_dek_version("email")
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        db.store()
            .scoped(scope)
            .envelope()
            .open_secret(&master, "email")
            .await
            .unwrap(),
        old_plaintext
    );

    // Re-encrypting an already-current secret is a no-op.
    let again = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .envelope()
        .reencrypt_secret(&env, &master, "email")
        .await
        .expect("reencrypt no-op");
    assert!(!again, "an already-current secret is not re-encrypted");
}

#[tokio::test]
async fn crypto_shred_makes_tenant_unreadable_while_sibling_is_unaffected() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let master = master_key(&env);

    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    provision(&db, &env, &master, scope_a).await;
    provision(&db, &env, &master, scope_b).await;

    put_secret(&db, &env, &master, scope_a, "email", b"tenant-a-pii").await;
    put_secret(&db, &env, &master, scope_b, "email", b"tenant-b-pii").await;

    // Both read before the shred.
    assert_eq!(
        db.store()
            .scoped(scope_a)
            .envelope()
            .open_secret(&master, "email")
            .await
            .unwrap(),
        b"tenant-a-pii"
    );
    assert_eq!(
        db.store()
            .scoped(scope_b)
            .envelope()
            .open_secret(&master, "email")
            .await
            .unwrap(),
        b"tenant-b-pii"
    );

    // Crypto-shred tenant A's KEK.
    db.store()
        .scoped(scope_a)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .envelope()
        .destroy_kek(&env)
        .await
        .expect("destroy kek");

    // Tenant A has no live KEK, and its data is permanently unreadable. The
    // ciphertext row STILL EXISTS on disk, but decryption fails (Encryption, not
    // NotFound): the data is crypto-shredded, not deleted.
    assert_eq!(
        db.store()
            .scoped(scope_a)
            .envelope()
            .active_kek_version()
            .await
            .unwrap(),
        None
    );
    let row_present: bool = sqlx::query(
        "SELECT EXISTS (SELECT 1 FROM encrypted_secrets \
         WHERE tenant_id = $1 AND environment_id = $2 AND purpose = 'email') AS present",
    )
    .bind(scope_a.tenant().to_string())
    .bind(scope_a.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("check row")
    .get("present");
    assert!(
        row_present,
        "the shredded tenant's ciphertext row is retained on disk"
    );
    assert!(
        matches!(
            db.store()
                .scoped(scope_a)
                .envelope()
                .open_secret(&master, "email")
                .await,
            Err(StoreError::Encryption)
        ),
        "the shredded tenant's data must be unrecoverable"
    );

    // The sibling tenant is entirely unaffected.
    assert_eq!(
        db.store()
            .scoped(scope_b)
            .envelope()
            .open_secret(&master, "email")
            .await
            .unwrap(),
        b"tenant-b-pii"
    );
}
