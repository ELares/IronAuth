// SPDX-License-Identifier: MIT OR Apache-2.0

//! The messaging ledger has a producer (issue #111).
//!
//! Before this, `MessageRepo::enqueue` had ZERO production callers. The ledger, the collapse,
//! the rate limit, the suppression check, the failover and both management endpoints were all
//! implemented, wired into the shipped binary, and covered by passing tests, and nothing ever
//! handed them a message. Three of issue #111's acceptance criteria were false for that reason
//! alone.
//!
//! This proves the door is open: a new-device notice delivered through the `VerificationSender`
//! seam lands a row in `messages` with a delivery job beside it.

use ironauth_env::Env;
use ironauth_oidc::message_sender::{MessagingVerificationSender, NEW_DEVICE_KIND};
use ironauth_oidc::{NewDeviceNotice, VerificationSender};
use ironauth_store::CorrelationId;
use ironauth_store::message_rate::RateBudget;
use ironauth_store::test_support::TestDatabase;
use sqlx::Row as _;

/// Provision the envelope keys the ledger seals a payload with.
///
/// `enqueue` seals the message body, so without a KEK and DEK for the scope it fails with
/// `StoreError::Encryption` before writing anything. The store's own message tests do the same
/// two calls; a producer that skipped them would look like it enqueued nothing.
async fn provision(db: &TestDatabase, env: &Env, scope: ironauth_store::Scope) {
    let acting = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env));
    acting
        .envelope()
        .provision_kek(env, &db.master_key())
        .await
        .expect("provision kek");
    acting
        .envelope()
        .provision_dek(env, &db.master_key())
        .await
        .expect("provision dek");
}

fn notice(scope: ironauth_store::Scope, recipient: &str) -> NewDeviceNotice<'_> {
    NewDeviceNotice {
        scope,
        recipient,
        user_agent: "Mozilla/5.0 (probe)",
        location_hint: "Lisbon, PT",
        disavowal_link: "https://issuer.test/disavow?t=single-use",
    }
}

#[tokio::test]
async fn a_new_device_notice_lands_in_the_ledger_with_a_delivery_job() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    provision(&db, &env, scope).await;
    let sender = MessagingVerificationSender::new(
        db.store().clone(),
        env.clone(),
        RateBudget::new(1_000, 3_600),
    );

    sender
        .deliver_new_device_notice(&notice(scope, "user@example.test"))
        .await;

    let row = sqlx::query(
        "SELECT COUNT(*) AS n FROM messages \
         WHERE tenant_id = $1 AND environment_id = $2 AND kind = $3",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(NEW_DEVICE_KIND)
    .fetch_one(db.owner_pool())
    .await
    .expect("count messages");
    let count: i64 = row.get("n");
    assert_eq!(
        count, 1,
        "a delivered notice must land a message; the ledger had no producer before this"
    );

    // The delivery job rides the SAME transaction as the row, which is the whole reason the
    // outbox exists: a message recorded with no job never sends.
    let jobs = sqlx::query(
        "SELECT COUNT(*) AS n FROM outbox_messages \
         WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("count jobs");
    let jobs: i64 = jobs.get("n");
    assert!(jobs >= 1, "a queued message must have a delivery job");
}

#[tokio::test]
async fn a_second_identical_notice_inside_the_window_collapses() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    provision(&db, &env, scope).await;
    let sender = MessagingVerificationSender::new(
        db.store().clone(),
        env.clone(),
        RateBudget::new(1_000, 3_600),
    );

    for _ in 0..3 {
        sender
            .deliver_new_device_notice(&notice(scope, "user@example.test"))
            .await;
    }

    let row = sqlx::query(
        "SELECT COUNT(*) AS n FROM messages \
         WHERE tenant_id = $1 AND environment_id = $2 AND kind = $3",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(NEW_DEVICE_KIND)
    .fetch_one(db.owner_pool())
    .await
    .expect("count");
    let count: i64 = row.get("n");
    assert_eq!(
        count, 1,
        "three identical notices in one window are one send; the collapse is what stops a \
         retried login mailing the user three times"
    );
}

#[tokio::test]
async fn an_undeliverable_recipient_is_recorded_rather_than_queued() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    provision(&db, &env, scope).await;
    let sender = MessagingVerificationSender::new(
        db.store().clone(),
        env.clone(),
        RateBudget::new(1_000, 3_600),
    );

    // Not an address. The login has already succeeded, so this must not panic and must not
    // queue anything.
    sender
        .deliver_new_device_notice(&notice(scope, "not-an-address"))
        .await;

    let row = sqlx::query("SELECT COUNT(*) AS n FROM messages WHERE tenant_id = $1")
        .bind(scope.tenant().to_string())
        .fetch_one(db.owner_pool())
        .await
        .expect("count");
    let count: i64 = row.get("n");
    assert_eq!(count, 0, "an unaddressable notice queues nothing");
}
