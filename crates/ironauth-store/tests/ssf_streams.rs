// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared Signals streams (issue #143).
//!
//! # What this owes
//!
//! A stream says WHERE this environment's security events go. Two properties matter more than
//! the CRUD, and both are the reason the surface above this can be trusted:
//!
//! - a receiver reaches exactly its own streams. #143 states it as an acceptance criterion, and
//!   the enforcement is not a check the handlers perform: `client_id` is a PARAMETER of every
//!   read and a CONJUNCT of every write, so a statement addressing another receiver's stream
//!   matches no row. The tests below drive each of the four operations from a second client and
//!   require the uniform not-found -- the same answer an absent handle gets, so a receiver
//!   cannot probe for the existence of somebody else's stream;
//! - the negotiation cannot widen. `events_delivered` is constrained at the DATABASE to be a
//!   subset of `events_requested`, so a transmitter cannot publish an event type the receiver
//!   never asked for however the code above is written.

#![cfg(feature = "testing")]

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ClientId, CorrelationId, NewSsfStream, Scope, SsfDelivery, SsfStreamId, SsfStreamStatus,
    SsfSubjectFormat, StoreError,
};

async fn seed_client(db: &TestDatabase, env: &Env, scope: Scope, name: &str) -> ClientId {
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .clients()
        .create(env, name)
        .await
        .expect("create client")
}

fn events() -> Vec<String> {
    vec![
        "https://schemas.openid.net/secevent/caep/event-type/session-revoked".to_owned(),
        "https://schemas.openid.net/secevent/caep/event-type/credential-change".to_owned(),
    ]
}

fn push_spec<'a>(
    id: &'a SsfStreamId,
    client_id: &'a ClientId,
    delivery: &'a SsfDelivery,
    requested: &'a [String],
    delivered: &'a [String],
    audience: &'a [String],
) -> NewSsfStream<'a> {
    NewSsfStream {
        id,
        client_id,
        delivery,
        events_requested: requested,
        events_delivered: delivered,
        // DELIBERATELY NOT THE COLUMN DEFAULTS. 0216 defaults `subject_format` to 'iss_sub' and
        // `status` to 'enabled', so a fixture carrying those cannot tell a value that was
        // written from one the column supplied.
        subject_format: SsfSubjectFormat::Email,
        audience,
        description: Some("the sweep receiver"),
    }
}

#[tokio::test]
async fn a_stream_round_trips_every_field_it_was_configured_with() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let client = seed_client(&db, &env, scope, "receiver").await;
    let id = SsfStreamId::generate(&env, &scope);
    let delivery = SsfDelivery::Push {
        endpoint_url: "https://receiver.example.com/events".to_owned(),
        secret_name: Some("ssf_push_receiver".to_owned()),
    };
    let requested = events();
    let delivered = vec![requested[0].clone()];
    let audience = vec!["https://receiver.example.com".to_owned()];

    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .ssf_streams()
        .create(
            &env,
            push_spec(&id, &client, &delivery, &requested, &delivered, &audience),
        )
        .await
        .expect("create the stream");

    let read = db
        .store()
        .scoped(scope)
        .ssf_streams()
        .get_for_client(&id, &client)
        .await
        .expect("read it back");

    assert_eq!(read.id, id);
    assert_eq!(read.client_id, client);
    assert_eq!(read.status, SsfStreamStatus::Enabled);
    assert_eq!(read.status_reason, None);
    assert_eq!(read.delivery, delivery);
    assert_eq!(read.events_requested, requested);
    assert_eq!(read.events_delivered, delivered);
    assert_eq!(read.subject_format, SsfSubjectFormat::Email);
    assert_eq!(read.audience, audience);
    assert_eq!(read.description.as_deref(), Some("the sweep receiver"));
}

#[tokio::test]
async fn a_second_receiver_reaches_none_of_the_four_operations() {
    // THE FENCE, driven from the other side. Each of the four answers the UNIFORM not-found:
    // the same answer an absent handle gets, so a receiver learns nothing about whether
    // somebody else's stream exists.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let owner = seed_client(&db, &env, scope, "owner").await;
    let intruder = seed_client(&db, &env, scope, "intruder").await;
    let id = SsfStreamId::generate(&env, &scope);
    let delivery = SsfDelivery::Poll;
    let requested = events();
    let audience = vec!["https://receiver.example.com".to_owned()];

    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .ssf_streams()
        .create(
            &env,
            push_spec(&id, &owner, &delivery, &requested, &requested, &audience),
        )
        .await
        .expect("create the stream");

    let read = db.store().scoped(scope).ssf_streams();
    assert!(
        matches!(
            read.get_for_client(&id, &intruder).await,
            Err(StoreError::NotFound)
        ),
        "a second receiver read another's stream"
    );
    assert!(
        read.list_for_client(&intruder, 50, None)
            .await
            .expect("list")
            .is_empty(),
        "a second receiver listed another's stream"
    );

    let write = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .ssf_streams();
    assert!(
        matches!(
            write
                .set_status(&env, &id, &intruder, SsfStreamStatus::Disabled, None)
                .await,
            Err(StoreError::NotFound)
        ),
        "a second receiver changed another's stream status"
    );
    assert!(
        matches!(
            write.delete(&env, &id, &intruder).await,
            Err(StoreError::NotFound)
        ),
        "a second receiver deleted another's stream"
    );

    // AND THE OWNER STILL HAS IT. Without this the four assertions above would pass against a
    // stream the intruder had actually destroyed, which is the failure they exist to catch.
    let survived = db
        .store()
        .scoped(scope)
        .ssf_streams()
        .get_for_client(&id, &owner)
        .await
        .expect("the owner's stream survived");
    assert_eq!(survived.status, SsfStreamStatus::Enabled);
}

#[tokio::test]
async fn the_transmitter_cannot_agree_to_send_more_than_was_asked_for() {
    // THE NEGOTIATION CANNOT WIDEN, and it is the DATABASE that says so: a caller that computed
    // the intersection wrongly is refused here rather than publishing an event type the
    // receiver never asked to receive.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let client = seed_client(&db, &env, scope, "receiver").await;
    let id = SsfStreamId::generate(&env, &scope);
    let delivery = SsfDelivery::Poll;
    let requested = vec![events()[0].clone()];
    let delivered = events();
    let audience = vec!["https://receiver.example.com".to_owned()];

    let outcome = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .ssf_streams()
        .create(
            &env,
            push_spec(&id, &client, &delivery, &requested, &delivered, &audience),
        )
        .await;
    assert!(
        outcome.is_err(),
        "a stream delivering more than it requested was written"
    );
}

#[tokio::test]
async fn a_paused_stream_still_retains_and_a_disabled_one_does_not() {
    // The distinction the three statuses exist for. `retaining_in_scope` is the fan-out's read,
    // and a paused stream missing from it is a backlog the receiver can never be given.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let client = seed_client(&db, &env, scope, "receiver").await;
    let requested = events();
    let audience = vec!["https://receiver.example.com".to_owned()];
    let delivery = SsfDelivery::Poll;

    let mut ids = Vec::new();
    for _ in 0..3 {
        let id = SsfStreamId::generate(&env, &scope);
        db.store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .ssf_streams()
            .create(
                &env,
                push_spec(&id, &client, &delivery, &requested, &requested, &audience),
            )
            .await
            .expect("create");
        ids.push(id);
    }

    let write = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .ssf_streams();
    write
        .set_status(
            &env,
            &ids[1],
            &client,
            SsfStreamStatus::Paused,
            Some("maintenance"),
        )
        .await
        .expect("pause");
    write
        .set_status(&env, &ids[2], &client, SsfStreamStatus::Disabled, None)
        .await
        .expect("disable");

    let retaining = db
        .store()
        .scoped(scope)
        .ssf_streams()
        .retaining_in_scope(50)
        .await
        .expect("the fan-out read");
    let kept: Vec<SsfStreamId> = retaining.iter().map(|stream| stream.id).collect();
    assert!(kept.contains(&ids[0]), "the enabled stream was dropped");
    assert!(
        kept.contains(&ids[1]),
        "the PAUSED stream was dropped, losing its backlog"
    );
    assert!(!kept.contains(&ids[2]), "the disabled stream was retained");

    let paused = db
        .store()
        .scoped(scope)
        .ssf_streams()
        .get_for_client(&ids[1], &client)
        .await
        .expect("read the paused stream");
    assert_eq!(paused.status, SsfStreamStatus::Paused);
    assert_eq!(paused.status_reason.as_deref(), Some("maintenance"));
    assert!(paused.status.retains() && !paused.status.delivers());
}

#[tokio::test]
async fn a_handle_from_another_scope_is_not_found() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let other = db.seed_scope(&env).await;
    let client = seed_client(&db, &env, scope, "receiver").await;
    let foreign = SsfStreamId::generate(&env, &other);

    assert!(
        matches!(
            db.store()
                .scoped(scope)
                .ssf_streams()
                .get_for_client(&foreign, &client)
                .await,
            Err(StoreError::NotFound)
        ),
        "a handle minted in another scope resolved"
    );
}
