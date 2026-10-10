// SPDX-License-Identifier: MIT OR Apache-2.0

//! Durable identity material: real PostgreSQL, low-privilege scoped writes.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, PAIRWISE_SUBJECT_SALT_PURPOSE, PairwiseSaltMaterial, Scope, StoreError,
};

async fn ensure(db: &TestDatabase, env: &Env, scope: Scope) -> PairwiseSaltMaterial {
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .envelope()
        .ensure_pairwise_salt(env)
        .await
        .expect("durable salt")
}

async fn ciphertext(db: &TestDatabase, scope: Scope) -> Vec<u8> {
    sqlx::query_scalar(
        "SELECT ciphertext FROM encrypted_secrets WHERE tenant_id=$1 AND environment_id=$2 AND purpose=$3",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(PAIRWISE_SUBJECT_SALT_PURPOSE)
    .fetch_one(db.owner_pool())
    .await
    .expect("stored ciphertext")
}

async fn creation_audits(db: &TestDatabase) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action='encrypted_secret.put'")
        .fetch_one(db.owner_pool())
        .await
        .expect("audit count")
}

#[tokio::test]
async fn retry_restart_and_key_rotation_preserve_identity() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    assert!(matches!(
        db.store().scoped(scope).envelope().pairwise_salt().await,
        Err(StoreError::NotFound)
    ));
    assert_eq!(creation_audits(&db).await, 0);
    let original = ensure(&db, &env, scope).await;
    assert_eq!(format!("{original:?}"), "PairwiseSaltMaterial(<redacted>)");
    assert_eq!(ensure(&db, &env, scope).await, original);
    let sealed = ciphertext(&db, scope).await;
    assert!(!sealed.windows(32).any(|w| w == original.as_bytes()));
    assert_eq!(creation_audits(&db).await, 1);

    let restarted = db.restart_app_store().await;
    assert_eq!(
        restarted
            .scoped(scope)
            .envelope()
            .pairwise_salt()
            .await
            .unwrap(),
        original
    );
    let master = db.master_key();
    let acting = restarted
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env));
    acting.envelope().rotate_dek(&env, &master).await.unwrap();
    acting
        .envelope()
        .reencrypt_secret(&env, &master, PAIRWISE_SUBJECT_SALT_PURPOSE)
        .await
        .unwrap();
    assert_ne!(ciphertext(&db, scope).await, sealed);
    acting.envelope().rotate_kek(&env, &master).await.unwrap();
    assert_eq!(ensure(&db, &env, scope).await, original);
    assert_eq!(creation_audits(&db).await, 1);
}

#[tokio::test]
async fn concurrent_first_writers_on_independent_pools_converge() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(8));
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let store = db.restart_app_store().await;
        let actor = db.test_actor(&env);
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            let env = Env::system();
            barrier.wait().await;
            store
                .scoped(scope)
                .acting(actor, CorrelationId::generate(&env))
                .envelope()
                .ensure_pairwise_salt(&env)
                .await
                .expect("concurrent creation")
        }));
    }
    let mut values = Vec::new();
    for task in tasks {
        values.push(task.await.unwrap());
    }
    assert!(values.iter().all(|value| value == &values[0]));
    assert_eq!(creation_audits(&db).await, 1);
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM encrypted_secrets")
        .fetch_one(db.owner_pool())
        .await
        .unwrap();
    assert_eq!(rows, 1);
}

#[tokio::test]
async fn environment_and_tenant_scopes_have_distinct_material_and_reject_replay() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let a = db.seed_scope(&env).await;
    let b = Scope::new(a.tenant(), db.seed_environment(&env, a.tenant()).await);
    let c = db.seed_scope(&env).await;
    let value_a = ensure(&db, &env, a).await;
    for other in [b, c] {
        assert!(matches!(
            db.store().scoped(other).envelope().pairwise_salt().await,
            Err(StoreError::NotFound)
        ));
        assert_ne!(ensure(&db, &env, other).await, value_a);
        sqlx::query("UPDATE encrypted_secrets SET ciphertext=$1 WHERE tenant_id=$2 AND environment_id=$3 AND purpose=$4")
            .bind(ciphertext(&db, a).await)
            .bind(other.tenant().to_string()).bind(other.environment().to_string())
            .bind(PAIRWISE_SUBJECT_SALT_PURPOSE)
            .execute(db.owner_pool()).await.unwrap();
        assert!(matches!(
            db.store().scoped(other).envelope().pairwise_salt().await,
            Err(StoreError::Encryption)
        ));
    }
    assert_eq!(ensure(&db, &env, a).await, value_a);
}

#[tokio::test]
async fn reserved_material_cannot_be_replaced_or_repaired_after_corruption() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acting = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env));
    let master = db.master_key();
    for provisioned in [false, true] {
        if provisioned {
            ensure(&db, &env, scope).await;
        }
        assert!(matches!(
            acting
                .envelope()
                .put_secret(&env, &master, PAIRWISE_SUBJECT_SALT_PURPOSE, &[42; 32])
                .await,
            Err(StoreError::Invalid)
        ));
    }
    let mut damaged = ciphertext(&db, scope).await;
    *damaged.last_mut().unwrap() ^= 1;
    sqlx::query("UPDATE encrypted_secrets SET ciphertext=$1 WHERE purpose=$2")
        .bind(&damaged)
        .bind(PAIRWISE_SUBJECT_SALT_PURPOSE)
        .execute(db.owner_pool())
        .await
        .unwrap();
    assert!(matches!(
        acting.envelope().ensure_pairwise_salt(&env).await,
        Err(StoreError::Encryption)
    ));
    assert_eq!(ciphertext(&db, scope).await, damaged);
    assert_eq!(creation_audits(&db).await, 1);
}

#[tokio::test]
async fn shredded_keys_never_generate_a_replacement_identity() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    ensure(&db, &env, scope).await;
    let before = ciphertext(&db, scope).await;
    let acting = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env));
    acting.envelope().destroy_kek(&env).await.unwrap();
    assert!(matches!(
        acting.envelope().ensure_pairwise_salt(&env).await,
        Err(StoreError::Encryption)
    ));
    assert_eq!(ciphertext(&db, scope).await, before);
    assert_eq!(creation_audits(&db).await, 1);
}

#[tokio::test]
async fn failed_creation_audit_rolls_back_the_salt() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    sqlx::raw_sql("CREATE FUNCTION reject_salt_audit() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.action='encrypted_secret.put' THEN RAISE EXCEPTION 'injected salt audit failure'; END IF; RETURN NEW; END $$;
        CREATE TRIGGER reject_salt_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_salt_audit();")
        .execute(db.owner_pool()).await.unwrap();
    assert!(
        db.store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .envelope()
            .ensure_pairwise_salt(&env)
            .await
            .is_err()
    );
    assert!(matches!(
        db.store().scoped(scope).envelope().pairwise_salt().await,
        Err(StoreError::NotFound)
    ));
    assert_eq!(creation_audits(&db).await, 0);
    sqlx::query("DROP TRIGGER reject_salt_audit ON audit_log")
        .execute(db.owner_pool())
        .await
        .unwrap();
    ensure(&db, &env, scope).await;
    assert_eq!(creation_audits(&db).await, 1);
}

#[tokio::test]
async fn salt_and_encryption_material_do_not_enter_configuration_exports() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let before = ironauth_store::export_snapshot(&db.control_store().scoped(scope))
        .await
        .unwrap()
        .to_canonical_bytes()
        .unwrap();
    ensure(&db, &env, scope).await;
    let after = ironauth_store::export_snapshot(&db.control_store().scoped(scope))
        .await
        .unwrap()
        .to_canonical_bytes()
        .unwrap();
    assert_eq!(
        before, after,
        "environment identity must not be promoted as config"
    );
}
