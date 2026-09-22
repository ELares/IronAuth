// SPDX-License-Identifier: MIT OR Apache-2.0

//! The follower's event-APPLY, against two real databases (issue #155).
//!
//! The shipper tests prove the ordered stream lands on the follower; this is the other
//! half of the acceptance criterion — "users, credentials, and environment config
//! created in the home region are queryable in the follower within the configured lag
//! bound, verified by an integration test." A user registered in the home region, its
//! `user.created` event shipped, and the apply run makes the user QUERYABLE on the
//! follower through the same read path the runtime uses.
//!
//! The copy rides `row_to_json` + `json_populate_record`, so the sealed columns, the
//! blind indexes, and the password hash all travel byte-for-byte — the drift gate: a
//! migration that changes a replicated table's shape is exercised by this test.

use std::time::SystemTime;

use ironauth_env::Env;
use ironauth_store::replication::ReplicationShipper;
use ironauth_store::replication_apply::{apply_envelopes, shipped_domain_events};
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, IdentifierType, NewOutboxMessage, NewUserIdentifier, NewWebauthnCredential,
    UniquenessMode, UserIdentifierId, WEBHOOK_EVENT_CONSUMER,
};

/// THE ACCEPTANCE CRITERION'S INTEGRATION TEST: a home-region user becomes queryable
/// on the follower within the replication pass.
#[tokio::test]
async fn a_home_user_is_queryable_on_the_follower_after_ship_and_apply() {
    const PHC_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaGhhc2hoYXNo";
    let home = TestDatabase::start().await;
    let follower = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0F0A_0001);
    let (follow_env, _follow_clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0F0A_0001);
    let scope = home.seed_scope(&env).await;
    follower.seed_scope(&follow_env).await;

    // A real user in the home region, through the same registration path the login
    // surface uses.

    let (actor, corr) = (home.test_actor(&env), CorrelationId::generate(&env));
    let user_id = home
        .store()
        .scoped(scope)
        .acting(actor, corr)
        .users()
        .register(&env, "alice@example.test", PHC_HASH, None)
        .await
        .expect("register the home user");

    // The domain event the mutation would emit, on the home stream.
    let envelope = ironauth_store::event_catalog::envelope(
        "evt-apply-user",
        "user.created",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        0,
        &serde_json::json!({ "user_id": user_id.to_string(), "state": "active" }),
    )
    .expect("a registered event type");
    home.store()
        .scoped(scope)
        .outbox()
        .append_event(
            &env,
            &NewOutboxMessage {
                consumer: WEBHOOK_EVENT_CONSUMER,
                idempotency_key: "evt-apply-user",
                ordering_key: &user_id.to_string(),
                payload: envelope,
            },
        )
        .await
        .expect("enqueue the event");

    // SHIP the ordered stream, then APPLY it on the follower.
    let shipper = ReplicationShipper::new(home.owner_pool().clone(), follower.owner_pool().clone());
    let ship = shipper.ship(1_000).await.expect("the stream ships");
    assert_eq!(ship.partitions.len(), 1);
    assert_eq!(ship.partitions[0].lag_messages, 0, "caught up");

    let events = shipped_domain_events(follower.owner_pool())
        .await
        .expect("the follower's shipped domain events");
    assert_eq!(events.len(), 1, "one domain event on the follower");
    let apply = apply_envelopes(home.owner_pool(), follower.owner_pool(), &events)
        .await
        .expect("the apply runs");
    assert_eq!(apply.applied.len(), 1);
    assert_eq!(
        apply.applied[0].copied.as_deref(),
        Some("users"),
        "the user's row was copied"
    );

    // THE CRITERION: the user is QUERYABLE on the follower through the same read path
    // the runtime uses, with the same identity and the same credential hash.
    let replicated = follower
        .store()
        .scoped(scope)
        .users()
        .by_identifier("alice@example.test")
        .await
        .expect("the follower read runs")
        .expect("the user resolves on the follower");
    assert_eq!(
        replicated.id, user_id,
        "the follower serves the SAME user the home created"
    );
    assert_eq!(
        replicated.password_hash.as_str(),
        PHC_HASH,
        "the credential hash travelled intact"
    );

    // RE-APPLY converges (the upsert is idempotent), and the follower still has one user.
    let again = apply_envelopes(home.owner_pool(), follower.owner_pool(), &events)
        .await
        .expect("the re-apply runs");
    assert_eq!(again.applied.len(), 1);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(follower.owner_pool())
        .await
        .expect("count the follower users");
    assert_eq!(count, 1, "a re-apply must not duplicate");
}

/// THE WIDENING: a secondary identifier on the multi-identifier surface resolves on the
/// follower too — a login through ANY identifier works after failover, not just the
/// primary one the users row carries.
#[tokio::test]
async fn a_secondary_identifier_resolves_on_the_follower_after_apply() {
    const PHC_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaGhhc2hoYXNo";
    let home = TestDatabase::start().await;
    let follower = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0F0A_0002);
    let (follow_env, _follow_clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0F0A_0002);
    let scope = home.seed_scope(&env).await;
    follower.seed_scope(&follow_env).await;

    let (actor, corr) = (home.test_actor(&env), CorrelationId::generate(&env));
    let user_id = home
        .store()
        .scoped(scope)
        .acting(actor, corr)
        .users()
        .register(&env, "primary@example.test", PHC_HASH, None)
        .await
        .expect("register the home user");
    let identifier_id = UserIdentifierId::generate(&env, &scope);
    home.store()
        .scoped(scope)
        .acting(home.test_actor(&env), CorrelationId::generate(&env))
        .user_identifiers()
        .add(
            &env,
            NewUserIdentifier {
                id: &identifier_id,
                user_id: &user_id,
                identifier_type: IdentifierType::Email,
                raw: "secondary@example.test",
                verified: false,
                mode: UniquenessMode::EnvironmentWide,
                org: None,
            },
            None,
        )
        .await
        .expect("add the secondary identifier");

    let envelope = ironauth_store::event_catalog::envelope(
        "evt-apply-secondary",
        "user.created",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        0,
        &serde_json::json!({ "user_id": user_id.to_string(), "state": "active" }),
    )
    .expect("a registered event type");
    home.store()
        .scoped(scope)
        .outbox()
        .append_event(
            &env,
            &NewOutboxMessage {
                consumer: WEBHOOK_EVENT_CONSUMER,
                idempotency_key: "evt-apply-secondary",
                ordering_key: &user_id.to_string(),
                payload: envelope,
            },
        )
        .await
        .expect("enqueue the event");

    let shipper = ReplicationShipper::new(home.owner_pool().clone(), follower.owner_pool().clone());
    shipper.ship(1_000).await.expect("the stream ships");
    let events = shipped_domain_events(follower.owner_pool())
        .await
        .expect("the shipped domain events");
    apply_envelopes(home.owner_pool(), follower.owner_pool(), &events)
        .await
        .expect("the apply runs");

    // The secondary identifier resolves on the follower through the same read the login
    // path uses.
    let resolved = follower
        .store()
        .scoped(scope)
        .user_identifiers()
        .resolve(IdentifierType::Email, "secondary@example.test")
        .await
        .expect("the follower resolution runs");
    assert_eq!(resolved.len(), 1, "the secondary identifier resolves");
    assert_eq!(
        resolved[0].user_id, user_id,
        "to the SAME user the home created"
    );
}

/// THE CREDENTIAL-FACTOR WIDENING: a passkey registered on home is present on the
/// follower after the apply — the "credentials replicate" half extended beyond the
/// password hash to the WebAuthn factor surface.
#[tokio::test]
async fn a_passkey_registered_on_home_is_present_on_the_follower_after_apply() {
    const PHC_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaGhhc2hoYXNo";
    let home = TestDatabase::start().await;
    let follower = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0F0A_0003);
    let (follow_env, _follow_clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0F0A_0003);
    let scope = home.seed_scope(&env).await;
    follower.seed_scope(&follow_env).await;

    let (actor, corr) = (home.test_actor(&env), CorrelationId::generate(&env));
    let user_id = home
        .store()
        .scoped(scope)
        .acting(actor, corr)
        .users()
        .register(&env, "fido@example.test", PHC_HASH, None)
        .await
        .expect("register the home user");

    // A passkey through the same registration path the WebAuthn ceremony uses.
    let credential = NewWebauthnCredential {
        credential_id: &[1, 2, 3, 4, 5],
        cose_public_key: &[6, 7, 8, 9],
        sign_count: 0,
        aaguid: &[0, 0, 0, 0],
        transports: &[],
        backup_eligible: false,
        backup_state: false,
        discoverable: None,
        nickname: "test-key",
        attestation_type: "none",
        attestation_verified: false,
        attestation_fmt: "none",
    };
    home.store()
        .scoped(scope)
        .acting(home.test_actor(&env), CorrelationId::generate(&env))
        .webauthn_credentials()
        .register(&env, &user_id, &credential)
        .await
        .expect("register the passkey");

    let envelope = ironauth_store::event_catalog::envelope(
        "evt-apply-fido",
        "user.created",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        0,
        &serde_json::json!({ "user_id": user_id.to_string(), "state": "active" }),
    )
    .expect("a registered event type");
    home.store()
        .scoped(scope)
        .outbox()
        .append_event(
            &env,
            &NewOutboxMessage {
                consumer: WEBHOOK_EVENT_CONSUMER,
                idempotency_key: "evt-apply-fido",
                ordering_key: &user_id.to_string(),
                payload: envelope,
            },
        )
        .await
        .expect("enqueue the event");

    let shipper = ReplicationShipper::new(home.owner_pool().clone(), follower.owner_pool().clone());
    shipper.ship(1_000).await.expect("the stream ships");
    let events = shipped_domain_events(follower.owner_pool())
        .await
        .expect("the shipped domain events");
    apply_envelopes(home.owner_pool(), follower.owner_pool(), &events)
        .await
        .expect("the apply runs");

    // The passkey is present on the follower through the same read the assertion path
    // uses, for the same subject.
    let has = follower
        .store()
        .scoped(scope)
        .webauthn_credentials()
        .has_any(&user_id)
        .await
        .expect("the follower factor read runs");
    assert!(has, "the passkey replicated with its user");
}
