// SPDX-License-Identifier: MIT OR Apache-2.0

//! The automated key rotation state machine, against a real database (issue #160).
//!
//! The acceptance criterion's core: "a full automated rotation (pending through
//! retired) completes on a test cadence with zero verification failures for an RP that
//! caches JWKS at the documented max TTL." The zero-failure property is structural: at
//! every instant the published JWKS contains every key that could still sign a live
//! token - the successor is published a full pre-publication window before it signs,
//! and the outgoing head stays published until its last token expires. This test drives
//! the machine on a test cadence and asserts the key set's transitions happen exactly
//! at the boundaries.

use std::time::SystemTime;

use ironauth_env::Env;
use ironauth_store::NewSigningKey;
use ironauth_store::key_rotation::{RotationPolicy, RotationStateMachine};
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{CorrelationId, SigningKeyId, SigningKeyMaterialKind};

/// The test cadence: a 10_000-second rotation with a 100-second pre-publication window
/// and a 50-second retirement buffer, so every boundary is reachable in a fast test.
fn test_policy() -> RotationPolicy {
    RotationPolicy {
        cadence_secs: 10_000,
        pre_publication_secs: 100,
        retirement_buffer_secs: 50,
    }
}

/// The day-one head: an `EdDSA` key active at `t0`.
async fn provision_day_one_head(
    db: &TestDatabase,
    env: &Env,
    scope: ironauth_store::Scope,
    t0: i64,
) {
    let id = SigningKeyId::generate(env, &scope);
    let mut seed = [0_u8; 32];
    env.entropy().fill_bytes(&mut seed);
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .signing_keys()
        .provision(
            env,
            NewSigningKey {
                id: &id,
                algorithm: "EdDSA",
                material_kind: SigningKeyMaterialKind::Ed25519Seed,
                material: &seed,
                publish_at_micros: t0,
                activate_at_micros: t0,
                retire_at_micros: None,
                expire_at_micros: None,
            },
        )
        .await
        .expect("provision the day-one head");
}

/// The published key set for the scope at `now`, by kid: the serving filter's rule -
/// published from `publish_at`, withdrawn after `expire_at`.
async fn published_kids(db: &TestDatabase, scope: ironauth_store::Scope, now: i64) -> Vec<String> {
    let keys = db
        .store()
        .scoped(scope)
        .signing_keys()
        .list()
        .await
        .expect("list the keys");
    keys.iter()
        .filter(|key| {
            key.publish_at_unix_micros <= now
                && key.expire_at_unix_micros.is_none_or(|expire| expire > now)
        })
        .map(|key| key.id.to_string())
        .collect()
}

/// THE CRITERION: a full rotation (pending -> current -> retiring -> retired) on a
/// test cadence, with the key set transitioning exactly at the boundaries.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn a_full_rotation_completes_with_the_key_set_transitioning_at_the_boundaries() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x40);
    let scope = db.seed_scope(&env).await;
    let t0 = 10_000_000_i64;
    provision_day_one_head(&db, &env, scope, t0).await;
    let actor = db.test_actor(&env);
    let policy = test_policy();
    let machine =
        RotationStateMachine::new(db.store(), scope, actor, CorrelationId::generate(&env));

    // t0 + 9900s: one hundred seconds before the rotation instant. The successor is
    // seeded and PRE-PUBLISHED; nothing has been promoted.
    let pre_pub_point = t0 + 9_900_000_000;
    let report = machine
        .advance(&env, policy, pre_pub_point, 1_000)
        .await
        .expect("the tick runs");
    assert_eq!(report.provisioned.len(), 1, "the successor is seeded");
    assert_eq!(report.promoted.len(), 0, "nothing is promoted yet");
    assert_eq!(
        published_kids(&db, scope, pre_pub_point).await.len(),
        2,
        "the pre-publication window has BOTH keys published: an RP caching at the max \
         TTL never misses the successor"
    );

    // t0 + 10000s: the rotation instant. The pending key becomes the head; the outgoing
    // head is marked retiring with its expiry (last token lifetime + buffer).
    let rotation_point = t0 + 10_000_000_000;
    let report = machine
        .advance(&env, policy, rotation_point, 1_000)
        .await
        .expect("the tick runs");
    assert_eq!(report.promoted.len(), 1, "the successor is promoted");
    assert_eq!(report.retiring.len(), 1, "the previous head is retiring");
    assert_eq!(
        published_kids(&db, scope, pre_pub_point).await.len(),
        2,
        "the retiring head stays published until its last token expires"
    );
    let keys = db
        .store()
        .scoped(scope)
        .signing_keys()
        .list()
        .await
        .expect("list the keys");
    let outgoing = keys
        .iter()
        .find(|key| key.id.to_string() == report.retiring[0].1)
        .expect("the outgoing key");
    let outgoing_expire = outgoing
        .expire_at_unix_micros
        .expect("the expiry is set at handoff");
    assert_eq!(
        outgoing_expire,
        rotation_point + 1_000_000_000 + 50_000_000,
        "the retiring key expires at last-token-lifetime plus the buffer"
    );

    // The audit rows for the handoff: promoted + retiring, in one transaction.
    let audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE tenant_id = $1 AND environment_id = $2 \
         AND action IN ('signing_key.promoted', 'signing_key.retiring')",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("the audit rows");
    assert_eq!(audits, 2, "the handoff emits both audit events");

    // t0 + 10000s + lifetime + buffer: the retiring key's expiry passed. It is
    // withdrawn from the published set, and the retired audit row is recorded.
    let withdrawal_point = rotation_point + 1_000_000_000 + 50_000_000;
    let keys = db
        .store()
        .scoped(scope)
        .signing_keys()
        .list()
        .await
        .expect("list the keys");
    eprintln!(
        "keys at withdrawal: {:?}",
        keys.iter()
            .map(|k| (
                k.id.to_string(),
                k.publish_at_unix_micros,
                k.activate_at_unix_micros,
                k.retire_at_unix_micros,
                k.expire_at_unix_micros
            ))
            .collect::<Vec<_>>()
    );
    let report = machine
        .advance(&env, policy, withdrawal_point, 1_000)
        .await
        .expect("the tick runs");
    assert_eq!(report.retired.len(), 1, "the retiring key's expiry passed");
    assert_eq!(
        published_kids(&db, scope, withdrawal_point).await.len(),
        1,
        "after expiry the JWKS holds only the current head"
    );
    let retired_audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE tenant_id = $1 AND environment_id = $2 \
         AND action = 'signing_key.retired'",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("the retired audit row");
    assert_eq!(retired_audits, 1);
}

/// THE BREAK-GLASS CRITERION: an explicit rotate-now-and-revoke operation that
/// promotes a fresh key immediately, withdraws the compromised key NOW (no retirement
/// window), requires the confirmation flag, and audits the invocation with the actor.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn break_glass_rotates_immediately_and_only_with_explicit_confirmation() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x41);
    let scope = db.seed_scope(&env).await;
    let t0 = 10_000_000_i64;
    provision_day_one_head(&db, &env, scope, t0).await;
    let actor = db.test_actor(&env);
    let machine =
        RotationStateMachine::new(db.store(), scope, actor, CorrelationId::generate(&env));
    let now = t0 + 1_000_000;

    // WITHOUT the confirmation flag the operation refuses outright.
    let refused = machine.break_glass(&env, now, false).await;
    assert!(
        refused.is_err(),
        "the confirmation flag is mandatory, not advisory"
    );

    // WITH the flag: the compromised key is withdrawn immediately (its expiry is NOW,
    // not lifetime+buffer), a fresh successor signs, and the invocation is audited.
    let report = machine
        .break_glass(&env, now, true)
        .await
        .expect("the break-glass runs");
    assert_eq!(report.provisioned.len(), 1, "a fresh successor is minted");
    assert_eq!(
        report.promoted.len(),
        1,
        "the successor is promoted immediately"
    );
    assert_eq!(report.retired.len(), 1, "the compromised key is withdrawn");

    let keys = db
        .store()
        .scoped(scope)
        .signing_keys()
        .list()
        .await
        .expect("list the keys");
    let outgoing = keys
        .iter()
        .find(|key| key.retire_at_unix_micros.is_some())
        .expect("the compromised key has its retirement stamped");
    assert_eq!(
        outgoing.retire_at_unix_micros,
        Some(now),
        "the compromised key retired at the break-glass instant"
    );
    assert_eq!(
        outgoing.expire_at_unix_micros,
        Some(now),
        "the compromised key expired IMMEDIATELY: no retirement window"
    );
    assert_eq!(
        published_kids(&db, scope, now).await.len(),
        1,
        "the JWKS holds only the fresh successor"
    );

    // The three audit rows: the invocation (with the acting actor), the promotion, and
    // the withdrawal.
    let audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE tenant_id = $1 AND environment_id = $2          AND action IN ('signing_key.break_glass', 'signing_key.promoted',                         'signing_key.retired')",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("the break-glass audit rows");
    assert_eq!(audits, 3, "invocation + promotion + withdrawal all audited");
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn a_full_rotation_is_idempotent_at_a_given_instant() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x42);
    let scope = db.seed_scope(&env).await;
    let t0 = 10_000_000_i64;
    provision_day_one_head(&db, &env, scope, t0).await;
    let actor = db.test_actor(&env);
    let policy = test_policy();
    let machine =
        RotationStateMachine::new(db.store(), scope, actor, CorrelationId::generate(&env));

    let pre_pub_point = t0 + 9_900_000_000;
    machine
        .advance(&env, policy, pre_pub_point, 1_000)
        .await
        .expect("the tick runs");
    let rotation_point = t0 + 10_000_000_000;
    machine
        .advance(&env, policy, rotation_point, 1_000)
        .await
        .expect("the tick runs");
    let withdrawal_point = rotation_point + 1_000_000_000 + 50_000_000;
    machine
        .advance(&env, policy, withdrawal_point, 1_000)
        .await
        .expect("the tick runs");

    // Idempotence: re-running the tick at the same instant does nothing new.
    let again = machine
        .advance(&env, policy, withdrawal_point, 1_000)
        .await
        .expect("the tick re-runs");
    assert_eq!(again.provisioned.len(), 0);
    assert_eq!(again.promoted.len(), 0);
    assert_eq!(again.retired.len(), 0);
}
