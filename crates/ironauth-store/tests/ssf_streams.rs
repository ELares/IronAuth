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

/// A ceiling every test here is comfortably under, so the limit is not what any of them
/// measures -- except the one that measures it.
const CEILING: u32 = 50;

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
            CEILING,
            None,
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
            CEILING,
            None,
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
            CEILING,
            None,
        )
        .await;
    // AND IT NAMES THE CONSTRAINT THAT REFUSED IT. `is_err()` alone passes for a `NotFound`
    // from the scope guard, for a `Conflict` on a duplicate handle, and for any future refusal
    // on an unrelated column -- so it would keep passing on the day this stopped being the
    // reason. The sibling IDOR test distinguishes its outcomes the same way.
    let Err(StoreError::Database(error)) = outcome else {
        panic!(
            "a stream delivering more than it requested was written, or was refused for a reason that is not the database's: {outcome:?}"
        );
    };
    let rendered = error.to_string();
    assert!(
        rendered.contains("ssf_streams_delivered_within_requested"),
        "the refusal came from the database but not from the subset constraint: {rendered}"
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
                CEILING,
                None,
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
async fn the_ceiling_is_a_conjunct_of_the_insert() {
    // THE COUNT IS EVALUATED INSIDE THE STATEMENT, not read first by the caller. A read-then-
    // write across two transactions lets N concurrent creates all see the same under-limit
    // count and all commit, so a receiver could exceed the bound by the number of requests it
    // sent at once. This drives the sequential case; what it pins is that the store refuses on
    // its own rather than trusting a count somebody else took.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let client = seed_client(&db, &env, scope, "receiver").await;
    let requested = events();
    let audience = vec!["https://receiver.example.com".to_owned()];
    let delivery = SsfDelivery::Poll;

    for _ in 0..2 {
        let id = SsfStreamId::generate(&env, &scope);
        db.store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .ssf_streams()
            .create(
                &env,
                push_spec(&id, &client, &delivery, &requested, &requested, &audience),
                2,
                None,
            )
            .await
            .expect("under the ceiling");
    }

    let third = SsfStreamId::generate(&env, &scope);
    let outcome = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .ssf_streams()
        .create(
            &env,
            push_spec(
                &third, &client, &delivery, &requested, &requested, &audience,
            ),
            2,
            None,
        )
        .await;
    assert!(
        matches!(outcome, Err(StoreError::QuotaExceeded)),
        "the third create was not refused: {outcome:?}"
    );

    // AND NOTHING WAS WRITTEN. A refusal that still inserted would leave the receiver holding a
    // stream it was told it did not get.
    let held = db
        .store()
        .scoped(scope)
        .ssf_streams()
        .list_for_client(&client, 50, None)
        .await
        .expect("list");
    assert_eq!(held.len(), 2, "the refused create left a row behind");

    // A SECOND RECEIVER IS UNAFFECTED: the ceiling counts one receiver's streams, not the
    // environment's.
    let other = seed_client(&db, &env, scope, "other receiver").await;
    let theirs = SsfStreamId::generate(&env, &scope);
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .ssf_streams()
        .create(
            &env,
            push_spec(
                &theirs, &other, &delivery, &requested, &requested, &audience,
            ),
            2,
            None,
        )
        .await
        .expect("another receiver has its own ceiling");
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

/// Provision the scope's envelope keys, which a queued SET is sealed under.
///
/// The management plane does this when it creates an environment (0028), so production always
/// has them; this harness stands a scope up directly and so has to do it itself. Without it
/// `queue` fails closed with `StoreError::Encryption` rather than storing a token in the clear,
/// which is the right failure and a confusing one to debug in a test.
///
/// IDEMPOTENT, because a test that seeds two streams calls this twice. `provision_kek` answers
/// `Conflict` when the scope already has one, which `ensure_scope_keys` in the repository treats
/// as success for the same reason.
async fn provision_envelope(db: &TestDatabase, env: &Env, scope: Scope) {
    let acting = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env));
    for (label, outcome) in [
        (
            "kek",
            acting.envelope().provision_kek(env, &db.master_key()).await.map(|_| ()),
        ),
        (
            "dek",
            acting.envelope().provision_dek(env, &db.master_key()).await.map(|_| ()),
        ),
    ] {
        match outcome {
            Ok(()) | Err(StoreError::Conflict) => {}
            Err(error) => panic!("provision the scope {label}: {error:?}"),
        }
    }
}

/// Seed one poll stream owned by `client`, and hand back its handle.
async fn poll_stream(db: &TestDatabase, env: &Env, scope: Scope, client: &ClientId) -> SsfStreamId {
    provision_envelope(db, env, scope).await;
    let id = SsfStreamId::generate(env, &scope);
    let requested = events();
    let audience = vec!["https://receiver.example.com".to_owned()];
    let delivery = SsfDelivery::Poll;
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .ssf_streams()
        .create(
            env,
            push_spec(&id, client, &delivery, &requested, &requested, &audience),
            CEILING,
            None,
        )
        .await
        .expect("create a poll stream");
    id
}

/// The per-stream owed-SET ceiling REFUSES, and refuses rather than evicting.
///
/// `ssf.max_owed_sets_per_stream` is what supplies this conjunct in production, and nothing
/// asserted it did anything: every other test queues a handful of SETs under the default of a
/// thousand, so deleting the `WHERE (SELECT count(*) ...) < $7` clause left the whole workspace
/// green. A bound no test approaches is a bound nobody has measured.
///
/// BOTH HALVES, because "refuses" and "evicts" are the two ways a full queue can behave and only
/// one of them is correct: silently dropping the oldest events is the failure the subsystem
/// exists to prevent, so the count after the refusal must still be the ceiling and the OLDEST
/// SET must still be there.
#[tokio::test]
async fn the_owed_ceiling_refuses_the_next_set_and_evicts_nothing() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let client = seed_client(&db, &env, scope, "receiver").await;
    let stream = poll_stream(&db, &env, scope, &client).await;

    let sets = db.store().scoped(scope);
    let sets = sets.ssf_stream_sets();
    for n in 0..3 {
        sets.queue(&env, &stream, &format!("evt_{n}"), "header.payload.sig", 3)
            .await
            .unwrap_or_else(|error| panic!("queue {n} under a ceiling of three: {error:?}"));
    }

    let outcome = sets
        .queue(&env, &stream, "evt_over", "header.payload.sig", 3)
        .await;
    assert!(
        matches!(outcome, Err(StoreError::QuotaExceeded)),
        "the fourth SET under a ceiling of three was not refused: {outcome:?}"
    );

    assert_eq!(
        sets.owed_count(&stream).await.expect("count"),
        3,
        "the refusal changed what the stream owes"
    );
    let owed = sets.owed(&stream, 10).await.expect("read what is owed");
    assert_eq!(
        owed.first().map(|set| set.jti.as_str()),
        Some("evt_0"),
        "the oldest SET was evicted to make room, which is the failure this bound prevents"
    );
    assert!(
        owed.iter().all(|set| set.jti != "evt_over"),
        "the refused SET was stored anyway"
    );

    // THE CEILING IS PER STREAM, not per environment. A second stream at the same ceiling must
    // still accept its own first SET, or the bound would be a shared budget one noisy receiver
    // could spend on behalf of every other.
    let neighbour = poll_stream(&db, &env, scope, &client).await;
    sets.queue(&env, &neighbour, "evt_0", "header.payload.sig", 3)
        .await
        .expect("a second stream has its own ceiling");
}

/// A token longer than the store will hold is refused BEFORE it is sealed.
///
/// The bound moved out of the schema when the column became ciphertext: a `CHECK` cannot read a
/// sealed value, so 0217 bounds the stored blob as a backstop and the rule about the TOKEN lives
/// in `queue`. That makes it a rule in code, which means it needs a test in a way a `CHECK` does
/// not.
#[tokio::test]
async fn a_set_larger_than_the_store_will_hold_is_refused() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let client = seed_client(&db, &env, scope, "receiver").await;
    let stream = poll_stream(&db, &env, scope, &client).await;
    let sets = db.store().scoped(scope);
    let sets = sets.ssf_stream_sets();

    // EXACTLY AT THE BOUND IS ACCEPTED, one byte over is not. A test that only drove a wildly
    // oversized value would pass against an off-by-one in either direction.
    let at_bound = "x".repeat(ironauth_store::MAX_SET_JWS_BYTES);
    sets.queue(&env, &stream, "evt_at_bound", &at_bound, CEILING)
        .await
        .expect("a token exactly at the bound is held");

    let over = "x".repeat(ironauth_store::MAX_SET_JWS_BYTES + 1);
    let outcome = sets.queue(&env, &stream, "evt_over", &over, CEILING).await;
    assert!(
        matches!(outcome, Err(StoreError::Invalid)),
        "a token one byte over the bound was accepted: {outcome:?}"
    );
    assert_eq!(
        sets.owed_count(&stream).await.expect("count"),
        1,
        "the oversized token was stored anyway"
    );

    // AND WHAT CAME BACK IS WHAT WENT IN. The seal is only correct if the round trip is exact:
    // a receiver must be handed the same bytes on every redelivery.
    let owed = sets.owed(&stream, 10).await.expect("read what is owed");
    assert_eq!(
        owed.first().map(|set| set.set_jws.as_str()),
        Some(at_bound.as_str()),
        "the sealed token did not round trip"
    );
}

/// A sealed token cannot be lifted from one row into another.
///
/// The seal is AAD-bound to the whole primary key, and this is what that buys: rewriting one
/// stream's ciphertext under a neighbour's identity FAILS TO OPEN rather than delivering one
/// receiver's event to another. Binding only the scope would leave every row in an environment
/// interchangeable, and nothing else in the schema would notice.
#[tokio::test]
async fn a_sealed_set_does_not_open_under_another_streams_identity() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let client = seed_client(&db, &env, scope, "receiver").await;
    let mine = poll_stream(&db, &env, scope, &client).await;
    let theirs = poll_stream(&db, &env, scope, &client).await;

    let scoped = db.store().scoped(scope);
    let sets = scoped.ssf_stream_sets();
    sets.queue(&env, &mine, "evt_0", "header.mine.sig", CEILING)
        .await
        .expect("queue a SET for the first stream");

    // Move the ciphertext across, exactly as a compromised writer or a bad restore would: the
    // row's own stream and jti change while the sealed bytes do not.
    db.execute_owner_sql(&format!(
        "UPDATE ssf_stream_sets SET stream_id = '{theirs}' \
         WHERE tenant_id = '{}' AND environment_id = '{}' AND stream_id = '{mine}'",
        scope.tenant(),
        scope.environment()
    ))
    .await;

    let outcome = sets.owed(&theirs, 10).await;
    assert!(
        matches!(outcome, Err(StoreError::Encryption)),
        "a ciphertext moved between streams opened anyway: {outcome:?}"
    );
}
