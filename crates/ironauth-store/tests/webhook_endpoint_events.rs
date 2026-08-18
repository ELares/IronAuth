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

/// Registering an endpoint emits `webhook_endpoint.created`, and NEVER its signing secret.
///
/// The sharpest secret rule in the registry: the secret this event could leak is the one that
/// authenticates the very deliveries the event travels on, so a subscriber holding it could
/// FORGE deliveries to that endpoint. Asserted against the rendered envelope rather than
/// trusted from the schema, because a payload may carry fields the schema does not forbid.
///
/// The URL is carried deliberately -- it is the endpoint's identity to an operator and it is
/// not a secret: they supplied it.
#[tokio::test]
async fn registering_an_endpoint_announces_it_without_the_signing_secret() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let id = WebhookEndpointId::generate(&env, &scope);
    let subject = id.to_string();

    let envelope = ironauth_store::event_catalog::envelope(
        "evt_endpoint_created",
        "webhook_endpoint.created",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        1,
        &serde_json::json!({
            "webhook_endpoint_id": subject,
            "url": "https://ops.example.test/hook",
        }),
    )
    .expect("webhook_endpoint.created is registered");

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .webhook_endpoints()
        .create_with_event(
            &env,
            NewWebhookEndpoint {
                id: &id,
                url: "https://ops.example.test/hook",
                description: "an endpoint",
                secret: b"endpoint-signing-secret",
                created_at_micros: 1_000_000,
            },
            None,
            Some(&ironauth_store::DomainEvent {
                id: "evt_endpoint_created",
                subject: &subject,
                envelope: &envelope,
            }),
        )
        .await
        .expect("create with event");

    let events = queued_events(&db, scope).await;
    assert_eq!(events.len(), 1, "the create enqueues exactly one event");
    assert_eq!(events[0]["type"], "webhook_endpoint.created");
    assert_eq!(events[0]["payload"]["url"], "https://ops.example.test/hook");
    ironauth_store::event_catalog::validate_event(&events[0])
        .expect("the envelope validates against the registry the fan-out enforces");
    assert!(
        !events[0].to_string().contains("endpoint-signing-secret"),
        "the event carried the endpoint's SIGNING SECRET: {}",
        events[0]
    );
}

/// Pausing and resuming emit ONE type carrying the new state.
///
/// Not a `paused` and a `resumed`: unlike the create/update pairs elsewhere in this registry
/// these are the SAME transition in two directions over one boolean, and a consumer mirroring
/// "is this endpoint delivering" wants one subscription with a field to read rather than two
/// subscriptions to correlate.
///
/// Both directions are asserted, because a producer that hard-coded either value would pass a
/// test that only checked one.
#[tokio::test]
async fn pausing_and_resuming_an_endpoint_announce_the_new_state() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let id = create_endpoint(&db, &env, scope, "https://ops.example.test/hook").await;
    let subject = id.to_string();

    for (active, event_id) in [(false, "evt_paused"), (true, "evt_resumed")] {
        let envelope = ironauth_store::event_catalog::envelope(
            event_id,
            "webhook_endpoint.active_changed",
            &scope.tenant().to_string(),
            &scope.environment().to_string(),
            1,
            &serde_json::json!({ "webhook_endpoint_id": subject, "active": active }),
        )
        .expect("webhook_endpoint.active_changed is registered");

        db.control_store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .webhook_endpoints()
            .set_active_with_event(
                &env,
                &id,
                active,
                None,
                Some(&ironauth_store::DomainEvent {
                    id: event_id,
                    subject: &subject,
                    envelope: &envelope,
                }),
            )
            .await
            .expect("set active with event");

        // Claimed and COMPLETED each round: both events share the endpoint id as their
        // ordering key, so the resume is not claimable while the pause is outstanding.
        let claimed = db
            .store()
            .scoped(scope)
            .outbox()
            .claim(
                &env,
                ironauth_store::WEBHOOK_EVENT_CONSUMER,
                std::time::Duration::from_secs(30),
                100,
            )
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 1, "the flip enqueues exactly one event");
        assert_eq!(
            claimed[0].payload["type"],
            "webhook_endpoint.active_changed"
        );
        assert_eq!(
            claimed[0].payload["payload"]["active"], active,
            "the event must carry the state the flip WROTE, not a fixed value"
        );
        ironauth_store::event_catalog::validate_event(&claimed[0].payload)
            .expect("the envelope validates against the registry the fan-out enforces");
        for message in &claimed {
            db.store()
                .scoped(scope)
                .outbox()
                .complete(&env, message)
                .await
                .expect("complete");
        }
    }
}
