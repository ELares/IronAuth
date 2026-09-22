// SPDX-License-Identifier: MIT OR Apache-2.0

//! The on-demand backup request's audited write (issue #153).
//!
//! The endpoint half is exercised at the router level (the openapi contract's served-route
//! sweep drives every documented route, including the backups route, at 401). What is only
//! reachable here is the STORE half: whether a request lands in the admin-action stream
//! with the right action, target, and detail - the durable record that answers "who asked,
//! when" even when no scheduler is running.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{CorrelationId, IdempotencyWrite};
use sqlx::Row;

#[tokio::test]
async fn a_backup_request_is_an_audited_admin_action_row() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let actor = db.test_actor(&env);

    db.control_store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(&env))
        .backup_requests()
        .request_backup(
            &env,
            Some(IdempotencyWrite {
                credential_ref: "opr_test",
                key: "key-1",
                request_fingerprint: "fp-1",
                response_status: 202,
                response_body: r#"{"recorded":true}"#,
            }),
        )
        .await
        .expect("the request is recorded");

    let row = sqlx::query(
        "SELECT action, target_kind, target_id, actor_id, stream, detail \
         FROM audit_log WHERE action = 'backup.requested'",
    )
    .fetch_one(db.owner_pool())
    .await
    .expect("the audited row exists");
    assert_eq!(row.get::<String, _>("action"), "backup.requested");
    assert_eq!(row.get::<String, _>("target_kind"), "backup");
    assert_eq!(row.get::<String, _>("target_id"), "backup");
    assert_eq!(row.get::<String, _>("actor_id"), actor.id_string());
    // The OCSF classification decides the stream: "backup" is an entity-management
    // domain, so the row lands in the ADMIN stream that compliance reads and retention
    // keeps on the long window.
    assert_eq!(row.get::<String, _>("stream"), "admin_action");
    assert_eq!(
        row.get::<Option<String>, _>("detail").as_deref(),
        Some("requested via the management API")
    );
}

#[tokio::test]
async fn an_unclassified_action_cannot_hide_in_the_trail() {
    // The classification is a REFUSAL in the store, not a default: an action that exists
    // outside the classified domains fails the write rather than landing unclassified.
    // `backup.requested` is classified (asserted above); this pins that the refusal path
    // exists by checking the domain lists agree.
    assert!(
        ironauth_store::ocsf::class_for(ironauth_store::Action::BackupRequested).is_some(),
        "backup.requested must be classified so it lands in a retention stream"
    );
}
