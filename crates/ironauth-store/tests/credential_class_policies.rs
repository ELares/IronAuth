// SPDX-License-Identifier: MIT OR Apache-2.0

//! Credential-class policy persistence and the user-handle immutability guarantee
//! at the store layer (issue #66, PR A), against a real database.
//!
//! These pin the store-side guarantees the composition and enforcement paths depend
//! on:
//!
//! - a credential-class policy upserts (the unique subject key collapses a re-set)
//!   and lists back per scope, with the tenant row and the (inert, M10-gated) group
//!   row both persisted;
//! - the attestation-config mode upserts and reads back (one row per scope);
//! - the WebAuthn user handle is IMMUTABLE at the storage layer: a raw adversarial
//!   UPDATE that would change a set handle is refused by the trigger, AND the
//!   low-privilege application role has no grant to name the column at all.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{CorrelationId, Scope, UserId};
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

#[tokio::test]
async fn credential_class_policy_upserts_and_lists_per_scope() {
    let env = Env::system();
    let db = TestDatabase::start().await;
    let scope = db.seed_scope(&env).await;
    let store = db.store();

    let acting = || {
        store
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
    };

    // Set the tenant-wide minimum to mfa, then RE-SET it to passkey: the unique subject
    // key collapses the upsert, so exactly one tenant row survives at the new class.
    acting()
        .credential_class_policies()
        .set(&env, "tenant", None, "mfa")
        .await
        .expect("set tenant mfa");
    acting()
        .credential_class_policies()
        .set(&env, "tenant", None, "passkey")
        .await
        .expect("upsert tenant passkey");
    // Attach a group-level minimum (the inert M10-gated seam): a distinct subject, so a
    // distinct row.
    acting()
        .credential_class_policies()
        .set(&env, "group", Some("grp_engineering"), "attested_passkey")
        .await
        .expect("set group attested");

    let policies = store
        .scoped(scope)
        .credential_class_policies()
        .list()
        .await
        .expect("list policies");
    assert_eq!(
        policies.len(),
        2,
        "tenant upsert collapsed, group is distinct"
    );
    let tenant = policies
        .iter()
        .find(|p| p.subject_kind == "tenant")
        .expect("tenant row");
    assert_eq!(tenant.min_class, "passkey", "the upsert took the new class");
    assert_eq!(tenant.subject_ref, None);
    let group = policies
        .iter()
        .find(|p| p.subject_kind == "group")
        .expect("group row");
    assert_eq!(group.min_class, "attested_passkey");
    assert_eq!(group.subject_ref.as_deref(), Some("grp_engineering"));

    // Remove the tenant row; the group row remains.
    acting()
        .credential_class_policies()
        .remove(&env, "tenant", None)
        .await
        .expect("remove tenant policy");
    let after = store
        .scoped(scope)
        .credential_class_policies()
        .list()
        .await
        .expect("list after remove");
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].subject_kind, "group");
}

#[tokio::test]
async fn attestation_config_upserts_and_reads_back() {
    let env = Env::system();
    let db = TestDatabase::start().await;
    let scope = db.seed_scope(&env).await;
    let store = db.store();

    // No row yet: the implicit default is mode 'none'.
    assert!(
        store
            .scoped(scope)
            .attestation_config()
            .get()
            .await
            .expect("get config")
            .is_none()
    );

    let acting = || {
        store
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
    };
    acting()
        .attestation_config()
        .set(&env, "none")
        .await
        .expect("set none");
    acting()
        .attestation_config()
        .set(&env, "direct")
        .await
        .expect("upsert direct");

    let config = store
        .scoped(scope)
        .attestation_config()
        .get()
        .await
        .expect("get config")
        .expect("a row exists");
    assert_eq!(
        config.mode, "direct",
        "the unique scope key collapsed the upsert"
    );
}

#[tokio::test]
async fn mds3_blob_cache_upsert_is_monotonic_and_never_rolls_back() {
    // The FIDO MDS3 processing rule (and the 0051 migration header) is that the
    // cache only advances: a refresh supersedes a STRICTLY HIGHER `no` sequence
    // number, so a replayed older-but-validly-signed BLOB cannot roll the cache
    // back and re-admit a model that a newer BLOB removed.
    let env = Env::system();
    let db = TestDatabase::start().await;
    let scope = db.seed_scope(&env).await;
    let store = db.store();

    let acting = || {
        store
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
    };
    let payload = |no: i64| serde_json::json!({ "no": no, "entries": [] });

    // Seed the cache at blob_no = 5.
    acting()
        .mds3_blob_cache()
        .upsert(&env, 5, 1, &payload(5), b"digest-5", 1, 1)
        .await
        .expect("seed blob_no 5");

    // Replay an OLDER blob_no = 3 (validly signed, just stale): the write is a
    // silent no-op, NOT an error, and the cache stays at 5.
    acting()
        .mds3_blob_cache()
        .upsert(&env, 3, 2, &payload(3), b"digest-3", 2, 2)
        .await
        .expect("replaying an older blob_no is not an error");
    let cached = store
        .scoped(scope)
        .mds3_blob_cache()
        .get()
        .await
        .expect("get")
        .expect("a row exists");
    assert_eq!(
        cached.blob_no, 5,
        "an older blob_no must not roll the cache back"
    );
    assert_eq!(
        cached.blob_digest, b"digest-5",
        "the superseding blob's payload survives the replay"
    );

    // A genuinely NEWER blob_no = 6 advances the cache.
    acting()
        .mds3_blob_cache()
        .upsert(&env, 6, 3, &payload(6), b"digest-6", 3, 3)
        .await
        .expect("newer blob_no 6");
    let cached = store
        .scoped(scope)
        .mds3_blob_cache()
        .get()
        .await
        .expect("get")
        .expect("a row exists");
    assert_eq!(
        cached.blob_no, 6,
        "a strictly newer blob_no advances the cache"
    );
    assert_eq!(cached.blob_digest, b"digest-6");
}

#[tokio::test]
async fn webauthn_user_handle_is_immutable_at_the_storage_layer() {
    let env = Env::system();
    let db = TestDatabase::start().await;
    let scope = db.seed_scope(&env).await;
    let user = register_user(&db, &env, scope, "handle-immutable@example.test").await;
    let owner = db.owner_pool();

    // Bind the handle ONCE (OLD is NULL, so the trigger allows the first set). The owner
    // connection bypasses RLS and the column grant, exactly as a migration or the future
    // PR B ceremony writer would set it.
    sqlx::query("UPDATE users SET webauthn_user_handle = $1 WHERE id = $2")
        .bind(vec![0xAB_u8; 32])
        .bind(user.to_string())
        .execute(owner)
        .await
        .expect("first bind of the handle is allowed");

    // An idempotent no-op UPDATE (same value) passes: the trigger only fires on a CHANGE.
    sqlx::query("UPDATE users SET webauthn_user_handle = $1 WHERE id = $2")
        .bind(vec![0xAB_u8; 32])
        .bind(user.to_string())
        .execute(owner)
        .await
        .expect("re-setting the same handle is a no-op, not a mutation");

    // Changing a SET handle is refused by the trigger, even as the owner (the storage-
    // layer half of the guarantee: the Kratos #4519 bug class cannot happen).
    let changed = sqlx::query("UPDATE users SET webauthn_user_handle = $1 WHERE id = $2")
        .bind(vec![0xCD_u8; 32])
        .bind(user.to_string())
        .execute(owner)
        .await;
    let error = changed.expect_err("mutating a set handle must be refused");
    assert!(
        error.to_string().contains("immutable"),
        "the immutability trigger must fire, got: {error}"
    );
    // The stored handle is unchanged.
    let stored: Vec<u8> = sqlx::query("SELECT webauthn_user_handle FROM users WHERE id = $1")
        .bind(user.to_string())
        .fetch_one(owner)
        .await
        .expect("read handle")
        .get("webauthn_user_handle");
    assert_eq!(
        stored,
        vec![0xAB_u8; 32],
        "the handle survived the mutation attempt"
    );

    // The low-privilege application role has NO grant to name the column at all (the
    // other, least-privilege half of the guarantee): a raw UPDATE as the app role is
    // refused at the privilege layer, before the trigger even runs.
    let app = db.app_pool();
    let denied = sqlx::query("UPDATE users SET webauthn_user_handle = $1 WHERE id = $2")
        .bind(vec![0xEF_u8; 32])
        .bind(user.to_string())
        .execute(app)
        .await;
    assert!(
        denied.is_err(),
        "the application role must have no privilege to update webauthn_user_handle"
    );
}
