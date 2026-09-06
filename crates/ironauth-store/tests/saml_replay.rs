// SPDX-License-Identifier: MIT OR Apache-2.0

//! What makes a SAML response usable exactly once (issue #139), over a real database.
//!
//! # Two defences, and the connection chooses which applies
//!
//! An outstanding request is the strong one. A response carries `InResponseTo`, and unless it
//! names a request THIS deployment issued and has not yet consumed, it is refused: that is what
//! makes a captured response useless a second time and a response nobody asked for useless the
//! first. It is the CVE-2026-9098 defence.
//!
//! The assertion replay cache stands in for it when an operator opts into IdP-initiated sign-in.
//! There is no request to correlate then, so the assertion's own ID is remembered for its
//! validity window instead. It is strictly weaker, which is why opting in also bounds that
//! window.
//!
//! # Concurrency is the point, not a detail
//!
//! #139 asks for the replay cache to be proven under concurrency, and both defences here are
//! written as ONE statement for that reason: a read followed by a write admits two redemptions
//! of one response, and that window is exactly what an attacker replaying a captured assertion is
//! aiming at. Tests that only redeem twice in sequence would pass against the broken shape.

#![cfg(feature = "testing")]

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, NewSamlConnection, OrganizationId, SamlConnectionId, Scope, StoreError,
};
use serde_json::json;

fn now_micros(env: &Env) -> i64 {
    i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("after epoch")
            .as_micros(),
    )
    .expect("fits i64")
}

async fn seed_org(db: &TestDatabase, env: &Env, scope: Scope, name: &str) -> OrganizationId {
    let id = OrganizationId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .organizations(scope)
        .create(env, &id, now_micros(env), name, None)
        .await
        .expect("create organization");
    id
}

async fn connect(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    organization: &OrganizationId,
    idp_entity_id: &str,
) -> SamlConnectionId {
    let id = SamlConnectionId::generate(env, &scope);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .saml_connections()
        .create(
            env,
            NewSamlConnection {
                id: &id,
                organization_id: organization,
                display_name: "Okta",
                idp_entity_id,
                idp_sso_url: "https://idp.example/sso",
                sp_entity_id: "https://ironauth.example/saml/metadata",
                acs_url: "https://ironauth.example/saml/acs",
                allow_unsolicited: false,
                clock_skew_secs: 30,
                max_assertion_age_secs: 300,
                nameid_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                attribute_mapping: &json!({}),
                require_encrypted_assertion: false,
            },
            None,
            None,
        )
        .await
        .expect("create the SAML connection");
    id
}

#[tokio::test]
async fn a_request_is_redeemed_once_and_carries_its_relay_state_back() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &org, "https://idp.example/entity").await;
    let store = db.store().scoped(scope);
    let now = now_micros(&env);

    store
        .saml_replay()
        .issue_request(
            &connection,
            "_req_1",
            Some("/dashboard"),
            None,
            now,
            now + 300_000_000,
        )
        .await
        .expect("issue the request");

    let relay = store
        .saml_replay()
        .consume_request(&connection, "_req_1", now)
        .await
        .expect("the response names a live request");
    assert_eq!(
        relay.relay_state.as_deref(),
        Some("/dashboard"),
        "the relay state did not come back, so the browser lands nowhere"
    );
    // AND THE BINDING THIS REQUEST WAS ISSUED WITHOUT, which is the shape a pre-0200 row and an
    // unsolicited response both present. `None` here is what the transport reads as "nothing to
    // compare"; see migration 0200 for why that is not a loophole.
    assert_eq!(relay.browser_binding_sha256, None);

    // A SECOND RESPONSE NAMING IT IS REFUSED. This is the replay, and it is the ordinary shape:
    // somebody captured the POST body and sent it again.
    let replayed = store
        .saml_replay()
        .consume_request(&connection, "_req_1", now)
        .await;
    assert!(
        matches!(replayed, Err(StoreError::NotFound)),
        "a captured response was accepted twice: {replayed:?}"
    );
}

#[tokio::test]
async fn a_request_that_was_never_issued_is_indistinguishable_from_one_already_used() {
    // THE FOUR REFUSALS ARE ONE ANSWER, deliberately. Unknown, expired, already consumed and
    // another connection's all answer `NotFound`, because a caller who could tell them apart
    // could probe: "already used" says a real session existed and "unknown" does not.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let ours = connect(&db, &env, scope, &org, "https://idp.example/entity").await;
    let theirs = connect(&db, &env, scope, &org, "https://other.example/entity").await;
    let store = db.store().scoped(scope);
    let now = now_micros(&env);

    // NEVER ISSUED.
    let unknown = store
        .saml_replay()
        .consume_request(&ours, "_never_issued", now)
        .await;
    assert!(matches!(unknown, Err(StoreError::NotFound)));

    // EXPIRED. Issued with a deadline already behind the clock the redemption is given.
    store
        .saml_replay()
        .issue_request(
            &ours,
            "_req_expired",
            None,
            None,
            now - 2_000_000,
            now - 1_000_000,
        )
        .await
        .expect("issue");
    let expired = store
        .saml_replay()
        .consume_request(&ours, "_req_expired", now)
        .await;
    assert!(
        matches!(expired, Err(StoreError::NotFound)),
        "an expired request was redeemed: {expired:?}"
    );

    // ANOTHER CONNECTION'S. The request is live, and it is not this connection's to redeem: a
    // response signed by one identity provider must not consume a request issued to another.
    store
        .saml_replay()
        .issue_request(&ours, "_req_ours", None, None, now, now + 300_000_000)
        .await
        .expect("issue");
    let crossed = store
        .saml_replay()
        .consume_request(&theirs, "_req_ours", now)
        .await;
    assert!(
        matches!(crossed, Err(StoreError::NotFound)),
        "one connection redeemed another's request: {crossed:?}"
    );
    // AND IT IS STILL REDEEMABLE BY ITS OWN CONNECTION, which is what proves the refusal above
    // was a refusal and not a consumption.
    store
        .saml_replay()
        .consume_request(&ours, "_req_ours", now)
        .await
        .expect("the request is still live for the connection it was issued to");
}

#[tokio::test]
async fn concurrent_responses_naming_one_request_admit_exactly_one() {
    // THE ASSERTION #139 ASKS FOR. A read followed by a write admits both, and the window is
    // exactly the one an attacker replaying a captured response is aiming at. The redemption is
    // one conditional UPDATE for that reason, and this is what measures it: sequential redemption
    // would pass against the broken shape.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &org, "https://idp.example/entity").await;
    let now = now_micros(&env);

    db.store()
        .scoped(scope)
        .saml_replay()
        .issue_request(
            &connection,
            "_req_race",
            Some("/after"),
            None,
            now,
            now + 300_000_000,
        )
        .await
        .expect("issue the request");

    let attempts = 8;
    let mut handles = Vec::with_capacity(attempts);
    for _ in 0..attempts {
        let store = db.store().clone();
        handles.push(tokio::spawn(async move {
            store
                .scoped(scope)
                .saml_replay()
                .consume_request(&connection, "_req_race", now)
                .await
        }));
    }
    let mut admitted = 0;
    for handle in handles {
        if handle.await.expect("the task ran").is_ok() {
            admitted += 1;
        }
    }
    assert_eq!(
        admitted, 1,
        "{attempts} concurrent responses naming one request admitted {admitted}; one-time use \
         has to hold under concurrency or it is not one-time use"
    );
}

#[tokio::test]
async fn concurrent_redemptions_of_one_assertion_admit_exactly_one() {
    // THE UNSOLICITED PATH. With no request to correlate, the assertion's own id is what stands
    // between a captured assertion and unlimited reuse, and the INSERT is the check: a
    // read-then-write would admit every concurrent arrival.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &org, "https://idp.example/entity").await;
    let now = now_micros(&env);

    let attempts = 8;
    let mut handles = Vec::with_capacity(attempts);
    for _ in 0..attempts {
        let store = db.store().clone();
        handles.push(tokio::spawn(async move {
            store
                .scoped(scope)
                .saml_replay()
                .admit_assertion(&connection, "_assertion_race", now, now + 300_000_000)
                .await
        }));
    }
    let mut admitted = 0;
    for handle in handles {
        if handle.await.expect("the task ran").is_ok() {
            admitted += 1;
        }
    }
    assert_eq!(
        admitted, 1,
        "{attempts} concurrent redemptions of one assertion admitted {admitted}"
    );

    // AND A LATER ONE IS STILL REFUSED, which is what makes it a cache and not a race window.
    let later = db
        .store()
        .scoped(scope)
        .saml_replay()
        .admit_assertion(&connection, "_assertion_race", now, now + 300_000_000)
        .await;
    assert!(matches!(later, Err(StoreError::Conflict)), "{later:?}");
}

#[tokio::test]
async fn one_assertion_id_is_per_connection_rather_than_per_environment() {
    // AN ASSERTION ID IS THE ISSUER'S TO CHOOSE, and two identity providers can mint the same
    // one: nothing in SAML makes them globally unique. Keyed per environment, one customer's IdP
    // emitting an id another had already used would lock that person out, and the failure would
    // look like a replay attack nobody could explain.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let first = connect(&db, &env, scope, &org, "https://idp-a.example/entity").await;
    let second = connect(&db, &env, scope, &org, "https://idp-b.example/entity").await;
    let store = db.store().scoped(scope);
    let now = now_micros(&env);

    store
        .saml_replay()
        .admit_assertion(&first, "_id_1234", now, now + 300_000_000)
        .await
        .expect("the first identity provider's assertion is admitted");
    store
        .saml_replay()
        .admit_assertion(&second, "_id_1234", now, now + 300_000_000)
        .await
        .expect(
            "a second identity provider reusing an id was refused, so one customer's IdP can \
             lock out another's users",
        );
}

#[tokio::test]
async fn a_request_cannot_be_issued_for_another_scopes_connection() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let ours = db.seed_scope(&env).await;
    let theirs = db.seed_scope(&env).await;
    let their_org = seed_org(&db, &env, theirs, "Initech").await;
    let their_connection = connect(&db, &env, theirs, &their_org, "https://idp.example/e").await;

    let refused = db
        .store()
        .scoped(ours)
        .saml_replay()
        .issue_request(
            &their_connection,
            "_req_x",
            None,
            None,
            now_micros(&env),
            now_micros(&env) + 300_000_000,
        )
        .await;
    assert!(
        matches!(refused, Err(StoreError::NotFound)),
        "a request was issued against another scope's connection: {refused:?}"
    );
}

#[tokio::test]
async fn a_request_cannot_be_issued_against_a_connection_that_does_not_exist() {
    // THE `WHERE EXISTS` INSIDE THE INSERT, which the id-scope check shadows for a FOREIGN handle
    // and which is the only thing covering a well-formed handle in THIS scope naming no row.
    //
    // Without it the insert reaches the foreign key and answers a raw constraint violation, so
    // starting a sign-in against a connection somebody deleted a moment ago is a 500 where it
    // should be a not-found. The test above could not see that: it hands a cross-scope handle,
    // which never reaches the statement.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let absent = SamlConnectionId::generate(&env, &scope);
    let now = now_micros(&env);

    let refused = db
        .store()
        .scoped(scope)
        .saml_replay()
        .issue_request(&absent, "_req_absent", None, None, now, now + 300_000_000)
        .await;
    assert!(
        matches!(refused, Err(StoreError::NotFound)),
        "issuing against a connection that does not exist was not a not-found: {refused:?}"
    );

    // AND NOTHING WAS WRITTEN, so the id is still free: a row inserted before the error would
    // make the retry a duplicate-key failure an operator cannot explain.
    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM saml_outstanding_requests WHERE id = $1")
            .bind("_req_absent")
            .fetch_one(db.owner_pool())
            .await
            .expect("count");
    assert_eq!(rows, 0, "the refused request was written anyway");
}
