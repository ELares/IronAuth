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
            None,
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

/// The `target_id` values recorded for `action` in `scope`, oldest first.
async fn audit_targets(db: &TestDatabase, scope: Scope, action: &str) -> Vec<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT target_id FROM audit_log \
         WHERE tenant_id = $1 AND environment_id = $2 AND action = $3 \
         ORDER BY occurred_at, id",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(action)
    .fetch_all(db.owner_pool())
    .await
    .expect("read audit targets")
}

#[tokio::test]
async fn an_overwriting_upsert_audits_the_row_that_exists_not_a_freshly_minted_id() {
    // Issue #436. These upserts mint a candidate id, use it as the audit `target_id`, and
    // then run `ON CONFLICT ... DO UPDATE` whose SET list does not include `id`. On the
    // overwrite branch the existing row keeps its own id, so the audit row pointed at an
    // identifier persisted NOWHERE: an investigator pivoting from a `*.set` audit row to
    // the configuration it changed found no row, and could not tell a first write from an
    // overwrite. Two of these also handed that phantom id to the operator through the CLI.
    //
    // The check is identity across the two calls, which is what a freshly minted id fails.
    let env = Env::system();
    let db = TestDatabase::start().await;
    let scope = db.seed_scope(&env).await;
    let store = db.store();
    let acting = || {
        store
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
    };

    // Each of the four id-returning upserts, driven twice with DIFFERENT values so the
    // second call genuinely takes the overwrite branch.
    let first = acting()
        .scope_step_up_policies()
        .set(&env, "urn:example:scope", Some("aal2"), Some(300), None)
        .await
        .expect("first step-up policy");
    let second = acting()
        .scope_step_up_policies()
        .set(&env, "urn:example:scope", Some("aal3"), Some(60), None)
        .await
        .expect("overwrite step-up policy");
    assert_eq!(
        first, second,
        "an overwrite keeps the existing row's id, so the caller and the CLI are handed an \
         identifier that resolves"
    );
    assert_eq!(
        audit_targets(&db, scope, "step_up.scope_policy.set").await,
        vec![first.to_string(), first.to_string()],
        "and BOTH audit rows name that same live row"
    );

    let first = acting()
        .credential_class_policies()
        .set(&env, "tenant", None, "passkey")
        .await
        .expect("first class policy");
    let second = acting()
        .credential_class_policies()
        .set(&env, "tenant", None, "mfa")
        .await
        .expect("overwrite class policy");
    assert_eq!(first, second, "the class policy keeps its row id");
    assert_eq!(
        audit_targets(&db, scope, "credential_class.policy.set").await,
        vec![first.to_string(), first.to_string()]
    );

    let first = acting()
        .attestation_config()
        .set(&env, "none")
        .await
        .expect("first attestation config");
    let second = acting()
        .attestation_config()
        .set(&env, "direct")
        .await
        .expect("overwrite attestation config");
    assert_eq!(first, second, "the attestation config keeps its row id");

    let first = acting()
        .aaguid_rules()
        .set(&env, b"0123456789abcdef", "allow")
        .await
        .expect("first aaguid rule");
    let second = acting()
        .aaguid_rules()
        .set(&env, b"0123456789abcdef", "deny")
        .await
        .expect("overwrite aaguid rule");
    assert_eq!(first, second, "the aaguid rule keeps its row id");
}

#[tokio::test]
async fn a_declined_mds3_refresh_writes_no_audit_row_at_all() {
    // Issue #436, the half that makes this upsert worse than its siblings. Its
    // `WHERE EXCLUDED.blob_no > ...` guard can make the statement write NOTHING for a
    // stale blob, and the audit row landed anyway: the trail recorded a cache refresh that
    // never happened. `RETURNING id` yields no row when the guard declines, and no row now
    // means no audit row.
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

    acting()
        .mds3_blob_cache()
        .upsert(&env, 5, 1, &payload(5), b"digest-5", 1, 1)
        .await
        .expect("seed blob_no 5");
    let after_seed = audit_targets(&db, scope, "mds3.blob_cache.refresh").await;
    assert_eq!(after_seed.len(), 1, "the seeding refresh is audited once");

    // The STALE replay writes nothing, so it must audit nothing.
    acting()
        .mds3_blob_cache()
        .upsert(&env, 3, 2, &payload(3), b"digest-3", 2, 2)
        .await
        .expect("a stale replay is not an error");
    assert_eq!(
        audit_targets(&db, scope, "mds3.blob_cache.refresh").await,
        after_seed,
        "a refresh the guard declined writes no audit row: the trail must not claim a \
         cache advance that did not happen"
    );

    // And a genuine advance is audited, naming the SAME row the seed created.
    acting()
        .mds3_blob_cache()
        .upsert(&env, 6, 3, &payload(6), b"digest-6", 3, 3)
        .await
        .expect("newer blob_no 6");
    let targets = audit_targets(&db, scope, "mds3.blob_cache.refresh").await;
    assert_eq!(targets.len(), 2, "the advance is audited");
    assert_eq!(
        targets[0], targets[1],
        "both name the one cache row rather than a fresh id per refresh"
    );
}

/// Claim the one webhook event outstanding in `scope`, completing it so the ordering key is
/// released for the next.
async fn claim_one_event(db: &TestDatabase, env: &Env, scope: Scope) -> serde_json::Value {
    let claimed = db
        .store()
        .scoped(scope)
        .outbox()
        .claim(
            env,
            ironauth_store::WEBHOOK_EVENT_CONSUMER,
            std::time::Duration::from_secs(30),
            100,
        )
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 1, "expected exactly one queued event");
    for message in &claimed {
        db.store()
            .scoped(scope)
            .outbox()
            .complete(env, message)
            .await
            .expect("complete");
    }
    claimed.into_iter().next().expect("one message").payload
}

/// Setting and removing a scope step-up policy emit distinct types.
///
/// A step-up policy is what a caller must satisfy before a token bearing that scope is issued,
/// so raising it hardens the scope and REMOVING it relaxes one. Removal is its own type
/// because a consumer must not read "policy removed" as "policy unchanged" -- that misreading
/// leaves a relaxed scope looking guarded.
///
/// Each half of the requirement is OMITTED when unset rather than sent as a sentinel: the set
/// below constrains only the ACR, and the test asserts `max_auth_age_secs` is absent.
#[tokio::test]
async fn setting_and_removing_a_step_up_policy_emit_distinct_types() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let token = "urn:example:events-scope";

    let set = ironauth_store::event_catalog::envelope(
        "evt_step_up_set",
        "step_up_policy.set",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        1,
        &serde_json::json!({ "scope_token": token, "min_acr": "aal2" }),
    )
    .expect("step_up_policy.set is registered");

    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .scope_step_up_policies()
        .set_with_event(
            &env,
            token,
            Some("aal2"),
            None,
            None,
            Some(&ironauth_store::DomainEvent {
                id: "evt_step_up_set",
                subject: token,
                envelope: &set,
            }),
        )
        .await
        .expect("set the policy");

    let first = claim_one_event(&db, &env, scope).await;
    assert_eq!(first["type"], "step_up_policy.set");
    assert_eq!(first["payload"]["min_acr"], "aal2");
    assert!(
        first["payload"].get("max_auth_age_secs").is_none(),
        "an unset half must be OMITTED, not sent as a sentinel: {first}"
    );
    ironauth_store::event_catalog::validate_event(&first)
        .expect("the envelope validates against the registry the fan-out enforces");

    let removed = ironauth_store::event_catalog::envelope(
        "evt_step_up_removed",
        "step_up_policy.removed",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        2,
        &serde_json::json!({ "scope_token": token }),
    )
    .expect("step_up_policy.removed is registered");

    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .scope_step_up_policies()
        .remove_with_event(
            &env,
            token,
            Some(&ironauth_store::DomainEvent {
                id: "evt_step_up_removed",
                subject: token,
                envelope: &removed,
            }),
        )
        .await
        .expect("remove the policy");

    let second = claim_one_event(&db, &env, scope).await;
    assert_eq!(
        second["type"], "step_up_policy.removed",
        "a removal RELAXES the scope; announcing it as a set would leave consumers believing \
         the scope is still guarded"
    );
    ironauth_store::event_catalog::validate_event(&second)
        .expect("the envelope validates against the registry the fan-out enforces");
}
