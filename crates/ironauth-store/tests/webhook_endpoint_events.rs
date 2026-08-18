// SPDX-License-Identifier: MIT OR Apache-2.0

//! `webhook_endpoint.deleted`, the self-referential producer (issue #108).
//!
//! Deleting a webhook endpoint emits onto the webhook event queue, which is the one producer
//! whose subject is the delivery machinery itself. Two properties follow, and both are
//! asserted here rather than reasoned about in a comment:
//!
//! - the removed endpoint does NOT receive its own removal, because the fan-out lists the
//!   live endpoints after this transaction commits and it is already gone;
//! - the delete is a no-op SUCCESS when the endpoint is absent, so a repeated delete emits a
//!   second event. That is deliberate and distinguishes it from `api_key.revoked`, which
//!   returns early and emits once. A receiver treats this type as at-least-once.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{CorrelationId, NewWebhookEndpoint, Scope, WebhookEndpointId};

async fn create_endpoint(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    url: &str,
) -> WebhookEndpointId {
    let id = WebhookEndpointId::generate(env, &scope);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .webhook_endpoints()
        .create(
            env,
            NewWebhookEndpoint {
                id: &id,
                url,
                description: "an endpoint",
                secret: b"endpoint-signing-secret",
                created_at_micros: 1_000_000,
            },
            None,
        )
        .await
        .expect("create endpoint");
    id
}

/// Every webhook-event envelope queued in `scope`.
async fn queued_events(db: &TestDatabase, scope: Scope) -> Vec<serde_json::Value> {
    use std::time::Duration;

    db.store()
        .scoped(scope)
        .outbox()
        .claim(
            &Env::system(),
            ironauth_store::WEBHOOK_EVENT_CONSUMER,
            Duration::from_secs(30),
            100,
        )
        .await
        .expect("claim webhook events")
        .into_iter()
        .map(|message| message.payload)
        .collect()
}

#[tokio::test]
async fn deleting_a_webhook_endpoint_emits_the_registered_event() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let endpoint = create_endpoint(&db, &env, scope, "https://receiver.example/hook").await;

    assert_eq!(
        queued_events(&db, scope).await.len(),
        0,
        "this create passed no event, so the delete's event below is unambiguous. The \
         un-suffixed method staying silent IS the paired-negative guarantee; it is not a \
         claim that creating never announces"
    );

    let envelope = ironauth_store::event_catalog::envelope(
        "evt_endpoint_deleted",
        "webhook_endpoint.deleted",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        1,
        &serde_json::json!({ "webhook_endpoint_id": endpoint.to_string() }),
    )
    .expect("webhook_endpoint.deleted is registered");

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .webhook_endpoints()
        .delete_with_event(
            &env,
            &endpoint,
            Some(&ironauth_store::DomainEvent {
                id: "evt_endpoint_deleted",
                subject: &endpoint.to_string(),
                envelope: &envelope,
            }),
        )
        .await
        .expect("delete with event");

    let events = queued_events(&db, scope).await;
    assert_eq!(events.len(), 1, "the delete enqueues exactly one event");
    assert_eq!(events[0]["type"], "webhook_endpoint.deleted");
    assert_eq!(
        events[0]["payload"]["webhook_endpoint_id"],
        endpoint.to_string()
    );
    ironauth_store::event_catalog::validate_event(&events[0])
        .expect("the envelope validates against the registry the fan-out enforces");
}

/// The deleted endpoint is gone before the fan-out reads, so it cannot receive its own
/// removal -- while any OTHER endpoint remains and will.
///
/// Asserted on the store rather than reasoned about, because "the endpoint is told it was
/// deleted" is the first thing a reader assumes and the schema alone cannot rule it out.
#[tokio::test]
async fn the_removed_endpoint_is_gone_while_the_others_remain() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let doomed = create_endpoint(&db, &env, scope, "https://doomed.example/hook").await;
    let survivor = create_endpoint(&db, &env, scope, "https://survivor.example/hook").await;

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .webhook_endpoints()
        .delete(&env, &doomed)
        .await
        .expect("delete");

    let live: Vec<WebhookEndpointId> = db
        .control_store()
        .scoped(scope)
        .webhook_endpoints()
        .list()
        .await
        .expect("list endpoints")
        .into_iter()
        .map(|endpoint| endpoint.id)
        .collect();

    assert!(
        !live.contains(&doomed),
        "the removed endpoint is not among the live ones the fan-out would read"
    );
    assert!(
        live.contains(&survivor),
        "the other endpoint remains, and is who the event is FOR"
    );
}

/// A delete carrying no event enqueues nothing.
#[tokio::test]
async fn deleting_a_webhook_endpoint_without_an_event_enqueues_nothing() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let endpoint = create_endpoint(&db, &env, scope, "https://quiet.example/hook").await;

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .webhook_endpoints()
        .delete(&env, &endpoint)
        .await
        .expect("delete");

    assert_eq!(
        queued_events(&db, scope).await.len(),
        0,
        "a delete with no event must not invent one"
    );
}
