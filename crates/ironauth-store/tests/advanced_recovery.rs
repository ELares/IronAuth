// SPDX-License-Identifier: MIT OR Apache-2.0

//! The advanced-recovery mode repositories (issue #82, PR 3) against a real Postgres: the
//! admin-approval queue, trusted-contact enrollment and single-use confirmations, and the
//! IDV-gated single-use case-bound session, plus cross-scope isolation (a row minted in one
//! scope is a uniform not-found under another).

use std::time::SystemTime;

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, NewRecoveryFlow, RecoveryEntryPoint, RecoveryFlowId, RecoveryMethod, Scope,
    StoreError, UserId,
};

/// The current instant in microseconds since the Unix epoch, read through the env clock seam
/// (the store uses the real system clock under `Env::system()`, so the confirmation / session
/// expiry must be based on it).
fn now_micros() -> i64 {
    let env = Env::system();
    i64::try_from(
        ironauth_env::Clock::now_utc(env.clock())
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("after epoch")
            .as_micros(),
    )
    .expect("fits i64")
}

/// Seed a HELD recovery flow of `method` for a fresh subject in `scope`, returning
/// `(flow_id, subject)`. `seed_byte` distinguishes the scope-wide-unique cancel digest.
async fn seed_flow(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    method: RecoveryMethod,
    seed_byte: u8,
) -> (RecoveryFlowId, UserId) {
    let subject = UserId::generate(env, &scope);
    let flow_id = RecoveryFlowId::generate(env, &scope);
    let digest = vec![seed_byte; 32];
    let spec = NewRecoveryFlow {
        id: &flow_id,
        subject: &subject,
        entry_point: RecoveryEntryPoint::LostAllFactors,
        recover_acr: "urn:ironauth:acr:pwd",
        cancel_token_digest: &digest,
        recipient: "recover@example.test",
        hold_until_unix_micros: Some(9_000_000_000_000_000),
        method,
    };
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .recovery_flows()
        .initiate(env, spec, 0)
        .await
        .expect("seed the recovery flow");
    (flow_id, subject)
}

#[tokio::test]
async fn admin_approval_queue_opens_approves_and_rejects() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (flow, subject) = seed_flow(&db, &env, scope, RecoveryMethod::AdminApproved, 1).await;

    // Open a pending approval; it is not yet approved.
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .recovery_approvals()
        .open(&env, &flow, &subject)
        .await
        .expect("open");
    assert!(
        !db.store()
            .scoped(scope)
            .recovery_approvals()
            .is_approved(&flow)
            .await
            .expect("is_approved"),
        "a pending approval is not approved"
    );

    // The control store approves it (only the control role holds the review grant).
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .recovery_approvals()
        .approve(&env, &flow, None)
        .await
        .expect("approve");
    assert!(
        db.store()
            .scoped(scope)
            .recovery_approvals()
            .is_approved(&flow)
            .await
            .expect("is_approved"),
        "an approved flow reports approved"
    );

    // A rejected flow (a fresh one) can never be approved afterward.
    let (flow2, subject2) = seed_flow(&db, &env, scope, RecoveryMethod::AdminApproved, 2).await;
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .recovery_approvals()
        .open(&env, &flow2, &subject2)
        .await
        .expect("open 2");
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .recovery_approvals()
        .reject(&env, &flow2, None)
        .await
        .expect("reject");
    // Re-approving a rejected case is a uniform not-found (no open approval to approve).
    assert!(matches!(
        db.control_store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .recovery_approvals()
            .approve(&env, &flow2, None)
            .await,
        Err(StoreError::NotFound)
    ));
}

#[tokio::test]
async fn trusted_contact_confirmations_are_single_use_and_distinct() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (flow, subject) = seed_flow(&db, &env, scope, RecoveryMethod::TrustedContact, 1).await;

    // Enroll two contacts and read them back (unsealed).
    let mut contact_ids = Vec::new();
    for address in ["alice@contact.test", "bob@contact.test"] {
        let id = db
            .store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .recovery_trusted_contacts()
            .enroll(&env, &subject, address)
            .await
            .expect("enroll");
        contact_ids.push(id);
    }
    let opened = db
        .store()
        .scoped(scope)
        .recovery_trusted_contacts()
        .list_opened(&subject)
        .await
        .expect("list");
    assert_eq!(opened.len(), 2);
    assert!(opened.iter().any(|c| c.address == "alice@contact.test"));
    assert!(opened.iter().any(|c| c.address == "bob@contact.test"));

    // Mint a pending confirmation per contact (single digest each).
    let expires = now_micros() + 86_400_000_000;
    let confirmations = db.store().scoped(scope);
    let mut digests = Vec::new();
    for (i, contact) in contact_ids.iter().enumerate() {
        let digest = vec![u8::try_from(100 + i).unwrap(); 32];
        db.store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .recovery_contact_confirmations()
            .create_pending(&env, &flow, contact, &digest, expires)
            .await
            .expect("create pending");
        digests.push(digest);
    }
    assert_eq!(
        confirmations
            .recovery_contact_confirmations()
            .count_total(&flow)
            .await
            .expect("total"),
        2
    );

    // Confirm the first contact's token: single-use (a replay latches nothing).
    let acting = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env));
    assert!(
        acting
            .recovery_contact_confirmations()
            .confirm(&env, &flow, &contact_ids[0], &digests[0])
            .await
            .expect("confirm")
    );
    assert!(
        !db.store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .recovery_contact_confirmations()
            .confirm(&env, &flow, &contact_ids[0], &digests[0])
            .await
            .expect("replay"),
        "a spent confirmation token is a single-use no-op"
    );
    assert_eq!(
        db.store()
            .scoped(scope)
            .recovery_contact_confirmations()
            .count_confirmed(&flow)
            .await
            .expect("confirmed"),
        1,
        "one distinct contact confirmed"
    );
}

#[tokio::test]
async fn idv_session_is_single_use_and_case_bound() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (flow, _subject) = seed_flow(&db, &env, scope, RecoveryMethod::Idv, 1).await;

    let state_digest = vec![7_u8; 32];
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .recovery_idv_sessions()
        .create(
            &env,
            &flow,
            "fixture",
            &state_digest,
            "case-nonce",
            now_micros() + 900_000_000,
        )
        .await
        .expect("create idv session");

    // The session resolves by its flow-bound state digest; a different digest (another flow's
    // state) selects nothing (case binding).
    assert!(
        db.store()
            .scoped(scope)
            .recovery_idv_sessions()
            .by_flow_state(&flow, &state_digest)
            .await
            .expect("by_flow_state")
            .is_some()
    );
    assert!(
        db.store()
            .scoped(scope)
            .recovery_idv_sessions()
            .by_flow_state(&flow, &[8_u8; 32])
            .await
            .expect("by_flow_state wrong")
            .is_none(),
        "a state minted for another case selects no session"
    );

    // Consume with a PASS verdict (single-use); a replay latches nothing.
    assert!(
        db.store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .recovery_idv_sessions()
            .consume(&env, &flow, &state_digest, "fixture", "pass")
            .await
            .expect("consume")
    );
    assert!(
        db.store()
            .scoped(scope)
            .recovery_idv_sessions()
            .passed_for_flow(&flow)
            .await
            .expect("passed")
    );
    assert!(
        !db.store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .recovery_idv_sessions()
            .consume(&env, &flow, &state_digest, "fixture", "pass")
            .await
            .expect("replay"),
        "a consumed IDV session is single-use"
    );
}

#[tokio::test]
async fn advanced_recovery_rows_are_scope_isolated() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let (flow, subject) = seed_flow(&db, &env, scope_a, RecoveryMethod::AdminApproved, 1).await;
    db.store()
        .scoped(scope_a)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .recovery_approvals()
        .open(&env, &flow, &subject)
        .await
        .expect("open in A");
    db.control_store()
        .scoped(scope_a)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .recovery_approvals()
        .approve(&env, &flow, None)
        .await
        .expect("approve in A");

    // Under scope B, flow A's approval is invisible: is_approved is false and an approve is a
    // uniform not-found (the cross-scope id is fenced out).
    assert!(
        !db.store()
            .scoped(scope_b)
            .recovery_approvals()
            .is_approved(&flow)
            .await
            .expect("cross-scope is_approved")
    );
    assert!(matches!(
        db.control_store()
            .scoped(scope_b)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .recovery_approvals()
            .approve(&env, &flow, None)
            .await,
        Err(StoreError::NotFound)
    ));
    // The IDV and confirmation reads are equally fenced under the wrong scope.
    assert!(
        db.store()
            .scoped(scope_b)
            .recovery_idv_sessions()
            .by_flow_state(&flow, &[7_u8; 32])
            .await
            .expect("cross-scope idv")
            .is_none()
    );
    assert_eq!(
        db.store()
            .scoped(scope_b)
            .recovery_contact_confirmations()
            .count_confirmed(&flow)
            .await
            .expect("cross-scope confirmed"),
        0
    );
}
