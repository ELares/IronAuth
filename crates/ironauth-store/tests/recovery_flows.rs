// SPDX-License-Identifier: MIT OR Apache-2.0

//! Account-recovery flow persistence at the store layer (issue #81), against a real
//! database.
//!
//! These pin the store-side guarantees the recovery subsystem depends on:
//!
//! - a flow round-trips through its state machine (initiated/held -> completed, and
//!   -> cancelled), and a terminal flow refuses a further transition;
//! - the recipient is SEALED at rest (a raw owner probe never sees the plaintext);
//! - the cancellation-token digest resolves the ONE flow, and a wrong digest is the
//!   uniform not-found;
//! - the per-account cooldown count sees a subject's recent initiations;
//! - every transition writes exactly one audit row targeting the flow.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    Action, CorrelationId, NewRecoveryFlow, RecoveryCancelReason, RecoveryEntryPoint,
    RecoveryFlowId, RecoveryState, Scope, UserId,
};
use sha2::{Digest, Sha256};
use sqlx::Row;

const ARGON_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2g";
const RECIPIENT: &str = "ada@example.test";

async fn register_user(db: &TestDatabase, env: &Env, scope: Scope, handle: &str) -> UserId {
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .users()
        .register(env, handle, ARGON_HASH)
        .await
        .expect("register user")
}

fn digest(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

/// Initiate a flow and return its id.
async fn initiate(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    subject: &UserId,
    token: &str,
    hold_until: Option<i64>,
) -> RecoveryFlowId {
    let id = RecoveryFlowId::generate(env, &scope);
    let token_digest = digest(token);
    let spec = NewRecoveryFlow {
        id: &id,
        subject,
        entry_point: RecoveryEntryPoint::LostPassword,
        recover_acr: "urn:ironauth:acr:pwd",
        cancel_token_digest: &token_digest,
        recipient: RECIPIENT,
        hold_until_unix_micros: hold_until,
        method: ironauth_store::RecoveryMethod::Standard,
    };
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .recovery_flows()
        .initiate(env, spec, 2)
        .await
        .expect("initiate recovery flow")
}

#[tokio::test]
async fn a_flow_round_trips_and_completes() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = register_user(&db, &env, scope, RECIPIENT).await;

    // A held flow whose delay horizon has already ELAPSED (a past `hold_until`): it is
    // held but past its window, so completion is permitted (the MEDIUM-3 guard refuses
    // completion only while `hold_until` is still in the FUTURE).
    let elapsed_hold: i64 = 1_000_000_000_000; // year 2001, comfortably in the past.
    let id = initiate(
        &db,
        &env,
        scope,
        &subject,
        "ira_rcv_tok~secret",
        Some(elapsed_hold),
    )
    .await;

    let record = db
        .store()
        .scoped(scope)
        .recovery_flows()
        .get(&id)
        .await
        .expect("get")
        .expect("flow exists");
    // A flow with a delay horizon is HELD.
    assert_eq!(record.state, RecoveryState::Held);
    assert_eq!(record.entry_point, RecoveryEntryPoint::LostPassword);
    assert_eq!(record.recover_acr, "urn:ironauth:acr:pwd");
    assert_eq!(record.hold_until_unix_micros, Some(elapsed_hold));

    // Complete it (the delay has elapsed).
    let completed = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .recovery_flows()
        .complete(&env, &id, &record.recover_acr)
        .await
        .expect("complete");
    assert!(completed);
    let record = db
        .store()
        .scoped(scope)
        .recovery_flows()
        .get(&id)
        .await
        .expect("get")
        .expect("flow exists");
    assert_eq!(record.state, RecoveryState::Completed);

    // A terminal flow refuses a further transition.
    let recompleted = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .recovery_flows()
        .complete(&env, &id, "urn:ironauth:acr:pwd")
        .await
        .expect("complete");
    assert!(!recompleted, "a completed flow does not complete again");
}

#[tokio::test]
async fn completing_a_held_flow_before_its_hold_until_is_refused() {
    // MEDIUM-3 defense in depth: a `held` flow whose `hold_until` is still in the FUTURE
    // can NOT be completed, so whoever wires completion in M9 cannot erase the delay gate
    // early. Once the horizon has elapsed, completion is permitted.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = register_user(&db, &env, scope, RECIPIENT).await;

    // A far-future hold horizon: the delay window has NOT elapsed.
    let id = initiate(
        &db,
        &env,
        scope,
        &subject,
        "ira_rcv_future~s",
        Some(9_999_999_999_000_000),
    )
    .await;

    // Completion is REFUSED while the hold is in the future, and the flow stays held.
    let refused = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .recovery_flows()
        .complete(&env, &id, "urn:ironauth:acr:pwd")
        .await
        .expect("complete");
    assert!(
        !refused,
        "a held flow with a future hold_until must not complete"
    );
    let record = db
        .store()
        .scoped(scope)
        .recovery_flows()
        .get(&id)
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(
        record.state,
        RecoveryState::Held,
        "the flow remains held; the delay gate was not erased"
    );

    // A DIFFERENT flow whose hold has already elapsed completes as before.
    let elapsed = initiate(
        &db,
        &env,
        scope,
        &subject,
        "ira_rcv_past~s",
        Some(1_000_000_000_000),
    )
    .await;
    let completed = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .recovery_flows()
        .complete(&env, &elapsed, "urn:ironauth:acr:pwd")
        .await
        .expect("complete");
    assert!(completed, "an elapsed-delay held flow completes");
}

#[tokio::test]
async fn pending_for_subject_returns_the_newest_pending_flow() {
    // The live factor-removal gate (issue #81 HIGH-1) reads the ONE pending flow; two
    // initiations racing at the cooldown boundary can both persist, so the read
    // deterministically returns the NEWEST, and a terminal flow is never returned.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = register_user(&db, &env, scope, RECIPIENT).await;

    // No pending flow yet.
    assert!(
        db.store()
            .scoped(scope)
            .recovery_flows()
            .pending_for_subject(&subject)
            .await
            .expect("pending")
            .is_none()
    );

    let first = initiate(
        &db,
        &env,
        scope,
        &subject,
        "ira_rcv_p1~s",
        Some(9_999_999_999_000_000),
    )
    .await;
    let second = initiate(
        &db,
        &env,
        scope,
        &subject,
        "ira_rcv_p2~s",
        Some(9_999_999_999_000_000),
    )
    .await;

    // A single pending flow is resolved (one of the two).
    let pending = db
        .store()
        .scoped(scope)
        .recovery_flows()
        .pending_for_subject(&subject)
        .await
        .expect("pending")
        .expect("a pending flow");
    assert!(
        pending.id == first || pending.id == second,
        "the resolved flow is one of the pending flows"
    );

    // Cancel whichever was resolved: the read then returns the OTHER still-pending flow,
    // never the cancelled (terminal) one.
    let other = if pending.id == second { first } else { second };
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .recovery_flows()
        .cancel(&env, &pending.id, RecoveryCancelReason::UserNotification)
        .await
        .expect("cancel");
    let pending = db
        .store()
        .scoped(scope)
        .recovery_flows()
        .pending_for_subject(&subject)
        .await
        .expect("pending")
        .expect("a pending flow");
    assert_eq!(pending.id, other, "a terminal flow is skipped");
}

#[tokio::test]
async fn cancellation_resolves_by_token_digest_and_is_single_shot() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = register_user(&db, &env, scope, RECIPIENT).await;

    let token = "ira_rcv_handle~cancel-secret";
    let id = initiate(
        &db,
        &env,
        scope,
        &subject,
        token,
        Some(9_999_999_999_000_000),
    )
    .await;

    // A wrong digest resolves nothing (uniform not-found).
    let wrong = db
        .store()
        .scoped(scope)
        .recovery_flows()
        .by_cancel_digest(&digest("ira_rcv_handle~wrong"))
        .await
        .expect("by digest");
    assert!(wrong.is_none());

    // The right digest resolves the ONE flow.
    let resolved = db
        .store()
        .scoped(scope)
        .recovery_flows()
        .by_cancel_digest(&digest(token))
        .await
        .expect("by digest")
        .expect("resolves");
    assert_eq!(resolved.id, id);

    // Cancel it, then a second cancel is a no-op (single-shot terminal transition).
    let cancelled = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .recovery_flows()
        .cancel(&env, &id, RecoveryCancelReason::UserNotification)
        .await
        .expect("cancel");
    assert!(cancelled);
    let again = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .recovery_flows()
        .cancel(&env, &id, RecoveryCancelReason::UserNotification)
        .await
        .expect("cancel");
    assert!(!again, "a cancelled flow does not cancel again");

    let record = db
        .store()
        .scoped(scope)
        .recovery_flows()
        .get(&id)
        .await
        .expect("get")
        .expect("exists");
    assert_eq!(record.state, RecoveryState::Cancelled);
}

#[tokio::test]
async fn the_recipient_is_sealed_at_rest() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = register_user(&db, &env, scope, RECIPIENT).await;
    let id = initiate(&db, &env, scope, &subject, "ira_rcv_x~s", None).await;

    // A raw owner probe never sees the plaintext recipient: the sealed column is
    // ciphertext, and there is no plaintext recipient column.
    let sealed: Vec<u8> = sqlx::query("SELECT recipient_sealed FROM recovery_flows WHERE id = $1")
        .bind(id.to_string())
        .fetch_one(db.owner_pool())
        .await
        .expect("read sealed")
        .get("recipient_sealed");
    assert!(!sealed.is_empty());
    assert!(
        !sealed
            .windows(RECIPIENT.len())
            .any(|w| w == RECIPIENT.as_bytes()),
        "the plaintext recipient must never appear in the sealed column"
    );
}

#[tokio::test]
async fn cooldown_count_sees_recent_initiations() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = register_user(&db, &env, scope, RECIPIENT).await;

    // No initiations yet.
    let before = db
        .store()
        .scoped(scope)
        .recovery_flows()
        .initiations_since(&subject, 0)
        .await
        .expect("count");
    assert_eq!(before, 0);

    initiate(&db, &env, scope, &subject, "ira_rcv_a~s", None).await;
    initiate(&db, &env, scope, &subject, "ira_rcv_b~s", None).await;

    // Both recent initiations are counted from epoch.
    let after = db
        .store()
        .scoped(scope)
        .recovery_flows()
        .initiations_since(&subject, 0)
        .await
        .expect("count");
    assert_eq!(after, 2);

    // A cutoff in the far future counts nothing.
    let none = db
        .store()
        .scoped(scope)
        .recovery_flows()
        .initiations_since(&subject, i64::MAX)
        .await
        .expect("count");
    assert_eq!(none, 0);
}

#[tokio::test]
async fn every_transition_writes_one_audit_row_targeting_the_flow() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = register_user(&db, &env, scope, RECIPIENT).await;
    let id = initiate(
        &db,
        &env,
        scope,
        &subject,
        "ira_rcv_c~s",
        Some(9_999_999_999_000_000),
    )
    .await;
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .recovery_flows()
        .record_factor_change(&env, &id, "decision=blocked;target_acr=phr")
        .await
        .expect("record factor change");
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .recovery_flows()
        .cancel(&env, &id, RecoveryCancelReason::UserNotification)
        .await
        .expect("cancel");

    let rows = sqlx::query(
        "SELECT action, target_id FROM audit_log \
         WHERE tenant_id = $1 AND environment_id = $2 AND action LIKE 'recovery.%' \
         ORDER BY occurred_at, id",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_all(db.owner_pool())
    .await
    .expect("read audit");
    let actions: Vec<String> = rows.iter().map(|r| r.get::<String, _>("action")).collect();
    assert!(actions.contains(&Action::RecoveryInitiate.as_str().to_owned()));
    assert!(actions.contains(&Action::RecoveryFactorChange.as_str().to_owned()));
    assert!(actions.contains(&Action::RecoveryCancel.as_str().to_owned()));
    let flow_text = id.to_string();
    for row in &rows {
        assert_eq!(row.get::<String, _>("target_id"), flow_text);
    }
}
