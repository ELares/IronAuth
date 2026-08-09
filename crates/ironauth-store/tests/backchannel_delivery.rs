// SPDX-License-Identifier: MIT OR Apache-2.0

//! The two store-side halves of back-channel logout fan-out (issues #34 and #104),
//! against a real database.
//!
//! Until #104 this suite pinned a dedicated `backchannel_logout_deliveries` queue. That
//! queue is retired: delivery is now a consumer on the generic outbox, so the store owes
//! the fan-out exactly two things, and this suite pins both.
//!
//! - `ClientSessionRepo::backchannel_participants` RESOLVES the recipients of one ended
//!   session as values: only clients that registered a non-empty `backchannel_logout_uri`,
//!   each with its OWN `sid` (never a co-scoped client's), and nothing outside the scope.
//!   It is a read rather than a write because the explode that consumes it lives in
//!   ironauth-oidc and `scripts/query-audit.sh` keeps scoped SQL in the repository module.
//!
//! - `OutboxRepo::enqueue_all` ENQUEUES that fan-out, and its two properties are the ones
//!   a lost logout hinges on:
//!
//!   * IDEMPOTENT. A key already enqueued is skipped, not raised on. The explode runs
//!     inside a consumer, so a lapsed lease re-runs it; under the RAISING `enqueue` the
//!     re-run would fail with a unique violation, fail the same way every retry, and
//!     dead-letter the session's whole fan-out with every RP the first pass had not
//!     reached left permanently un-notified.
//!   * ATOMIC. One transaction spans the slice, so a refused message commits none of its
//!     neighbours and the retry starts from a clean slate rather than an arbitrary prefix.
//!
//! It also pins the thing `0099_outbox_messages.sql:104` gets WRONG. That comment says
//! enqueuing twice for one domain fact is "a no-op rather than a double delivery, which
//! is what lets a producer retry an enqueue safely". The plain `enqueue` carries no
//! `ON CONFLICT` and RAISES, which is deliberate and load-bearing for a transactional
//! producer. A test asserts the raise, so the shipped comment cannot mislead the next
//! implementer into looping `enqueue` in a consumer.

use std::time::Duration;

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    BACKCHANNEL_LOGOUT_CONSUMER, ClientId, CorrelationId, NewOutboxMessage, SESSION_ENDED_CONSUMER,
    Scope, SessionEndCause, SessionId, UserId,
};
use sqlx::Row;

/// A far-future expiry (year 2100) in epoch microseconds, so a session is live until it is
/// explicitly ended.
const FAR_FUTURE_MICROS: i64 = 4_102_444_800_000_000;

/// Create a live SSO session in `scope` for `subject`.
async fn create_session(db: &TestDatabase, env: &Env, scope: Scope, subject: &str) -> SessionId {
    let id = SessionId::generate(env, &scope);
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .sessions()
        .rotate(
            env,
            &id,
            None,
            ironauth_store::NewSession {
                impersonation: None,
                subject,
                auth_methods: "pwd",
                auth_time_micros: 0,
                idle_expires_micros: FAR_FUTURE_MICROS,
                absolute_expires_micros: FAR_FUTURE_MICROS,
                user_agent: None,
                peer_ip: None,
            },
        )
        .await
        .expect("rotate session");
    id
}

/// Create a client, optionally register a `backchannel_logout_uri`, and bind a per-client
/// session (its `sid`) to `session`. Returns the client id and its sid.
async fn create_participant(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    session: &SessionId,
    logout_uri: Option<&str>,
) -> (ClientId, String) {
    let client = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .clients()
        .create(env, "rp")
        .await
        .expect("create client");
    if let Some(uri) = logout_uri {
        db.store()
            .scoped(scope)
            .acting(db.test_actor(env), CorrelationId::generate(env))
            .clients()
            .register_backchannel_logout(env, &client, Some(uri), false)
            .await
            .expect("register backchannel logout");
    }
    let sid = db
        .store()
        .scoped(scope)
        .client_sessions()
        .ensure_sid(env, session, &client.to_string(), 0)
        .await
        .expect("ensure sid");
    (client, sid)
}

/// End `session` as a logout (which enqueues one session-ended outbox message).
async fn end_session(db: &TestDatabase, env: &Env, scope: Scope, session: &SessionId) {
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .sessions()
        .revoke(env, session, SessionEndCause::LoggedOut, false, None)
        .await
        .expect("revoke session");
}

/// One per-RP delivery message for `(session, client)`, keyed exactly as the explode keys
/// it: the idempotency key and the ordering key are the SAME value, so every delivery is
/// its own singleton ordering group and no RP can queue behind another.
fn delivery<'a>(key: &'a str, uri: &str) -> NewOutboxMessage<'a> {
    NewOutboxMessage {
        consumer: BACKCHANNEL_LOGOUT_CONSUMER,
        idempotency_key: key,
        ordering_key: key,
        payload: serde_json::json!({ "logout_uri": uri }),
    }
}

/// How many messages are queued for `consumer` in `scope`, in any non-terminal state.
async fn pending_count(db: &TestDatabase, scope: Scope, consumer: &str) -> usize {
    db.store()
        .scoped(scope)
        .outbox()
        .pending(consumer, 1_000)
        .await
        .expect("pending")
        .len()
}

#[tokio::test]
async fn backchannel_participants_lists_only_registered_rps_each_with_its_own_sid() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = UserId::generate(&env, &scope).to_string();
    let session = create_session(&db, &env, scope, &subject).await;

    // Two clients register a back-channel URI; a third does NOT (it is not a participant).
    let (client_a, sid_a) =
        create_participant(&db, &env, scope, &session, Some("https://a.example/bc")).await;
    let (client_b, sid_b) =
        create_participant(&db, &env, scope, &session, Some("https://b.example/bc")).await;
    let (client_c, _sid_c) = create_participant(&db, &env, scope, &session, None).await;

    // The two sids are distinct per (client, session): an RP only ever learns its own.
    assert_ne!(sid_a, sid_b, "each client's sid is distinct");

    let participants = db
        .store()
        .scoped(scope)
        .client_sessions()
        .backchannel_participants(&session)
        .await
        .expect("resolve participants");

    assert_eq!(
        participants.len(),
        2,
        "only the two clients that registered a URI participate"
    );
    let found_a = participants
        .iter()
        .find(|p| p.client_id == client_a.to_string())
        .expect("client A participates");
    assert_eq!(found_a.sid, sid_a, "A carries its OWN sid");
    assert_eq!(found_a.logout_uri, "https://a.example/bc");
    let found_b = participants
        .iter()
        .find(|p| p.client_id == client_b.to_string())
        .expect("client B participates");
    assert_eq!(found_b.sid, sid_b, "B carries its OWN sid");
    assert_ne!(found_b.sid, sid_a, "B never learns A's sid");
    assert!(
        !participants
            .iter()
            .any(|p| p.client_id == client_c.to_string()),
        "a client with no backchannel_logout_uri is not a participant"
    );
}

#[tokio::test]
async fn backchannel_participants_refuses_a_session_from_another_scope() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let subject = UserId::generate(&env, &scope_a).to_string();
    let session = create_session(&db, &env, scope_a, &subject).await;
    create_participant(&db, &env, scope_a, &session, Some("https://a.example/bc")).await;

    // The uniform not-found, never an oracle for whether A's session exists.
    let refused = db
        .store()
        .scoped(scope_b)
        .client_sessions()
        .backchannel_participants(&session)
        .await;
    assert!(
        matches!(refused, Err(ironauth_store::StoreError::NotFound)),
        "a foreign-scope session id is refused uniformly"
    );
}

#[tokio::test]
async fn enqueue_all_inserts_every_message_and_reports_the_new_count() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let queued = db
        .store()
        .scoped(scope)
        .outbox()
        .enqueue_all(
            &env,
            &[
                delivery("ses_1:cli_a", "https://a.example/bc"),
                delivery("ses_1:cli_b", "https://b.example/bc"),
                delivery("ses_1:cli_c", "https://c.example/bc"),
            ],
        )
        .await
        .expect("enqueue the fan-out");
    assert_eq!(queued, 3, "every message is new");
    assert_eq!(
        pending_count(&db, scope, BACKCHANNEL_LOGOUT_CONSUMER).await,
        3
    );

    // An empty slice is a no-op rather than an error: a session with no participating RP
    // is the common case and must not fail its explode.
    let none = db
        .store()
        .scoped(scope)
        .outbox()
        .enqueue_all(&env, &[])
        .await
        .expect("empty fan-out");
    assert_eq!(none, 0);
    assert_eq!(
        pending_count(&db, scope, BACKCHANNEL_LOGOUT_CONSUMER).await,
        3
    );
}

#[tokio::test]
async fn a_re_run_of_enqueue_all_skips_what_is_there_and_adds_only_what_is_missing() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let outbox = db.store().scoped(scope);
    let outbox = outbox.outbox();

    // A first pass reaches two of the three RPs (the shape a lapsed lease leaves behind).
    let first = outbox
        .enqueue_all(
            &env,
            &[
                delivery("ses_1:cli_a", "https://a.example/bc"),
                delivery("ses_1:cli_b", "https://b.example/bc"),
            ],
        )
        .await
        .expect("first pass");
    assert_eq!(first, 2);

    // The re-run sees the SAME session and the SAME participants, plus the one it never
    // reached. It must not raise, and it must enqueue the missing RP. Under the raising
    // `enqueue` this call would fail on cli_a, fail identically on every retry, and
    // dead-letter the fan-out with cli_c NEVER notified.
    let second = outbox
        .enqueue_all(
            &env,
            &[
                delivery("ses_1:cli_a", "https://a.example/bc"),
                delivery("ses_1:cli_b", "https://b.example/bc"),
                delivery("ses_1:cli_c", "https://c.example/bc"),
            ],
        )
        .await
        .expect("a re-run must not raise on its own earlier output");
    assert_eq!(second, 1, "only the RP that was missing is newly enqueued");

    let pending = outbox
        .pending(BACKCHANNEL_LOGOUT_CONSUMER, 100)
        .await
        .expect("pending");
    assert_eq!(pending.len(), 3, "no RP is enqueued twice and none is lost");
    let mut keys: Vec<&str> = pending
        .iter()
        .map(|message| message.idempotency_key.as_str())
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["ses_1:cli_a", "ses_1:cli_b", "ses_1:cli_c"]);
}

#[tokio::test]
async fn enqueue_all_dedups_a_key_repeated_inside_one_call() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // The second message sees the first's row inside the SAME transaction, so the count
    // is the number of DISTINCT keys rather than the slice length.
    let queued = db
        .store()
        .scoped(scope)
        .outbox()
        .enqueue_all(
            &env,
            &[
                delivery("ses_1:cli_a", "https://a.example/bc"),
                delivery("ses_1:cli_a", "https://a.example/bc"),
            ],
        )
        .await
        .expect("enqueue with a repeated key");
    assert_eq!(queued, 1);
    assert_eq!(
        pending_count(&db, scope, BACKCHANNEL_LOGOUT_CONSUMER).await,
        1
    );
}

#[tokio::test]
async fn enqueue_all_commits_nothing_when_one_message_in_the_slice_is_refused() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // The middle message violates the migration's nonempty-key CHECK, so the database
    // refuses it. The whole slice must roll back: an arbitrary committed prefix would
    // leave the retry unable to tell which RPs were reached.
    let refused = db
        .store()
        .scoped(scope)
        .outbox()
        .enqueue_all(
            &env,
            &[
                delivery("ses_1:cli_a", "https://a.example/bc"),
                delivery("", "https://bad.example/bc"),
                delivery("ses_1:cli_c", "https://c.example/bc"),
            ],
        )
        .await;
    assert!(refused.is_err(), "a refused message fails the whole call");
    assert_eq!(
        pending_count(&db, scope, BACKCHANNEL_LOGOUT_CONSUMER).await,
        0,
        "the message BEFORE the refused one is rolled back too"
    );
}

#[tokio::test]
async fn the_raising_enqueue_still_raises_on_a_duplicate_key() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let scoped = db.store().scoped(scope);
    let outbox = scoped.outbox();

    outbox
        .enqueue(&env, &delivery("ses_1:cli_a", "https://a.example/bc"))
        .await
        .expect("first enqueue");
    // `0099_outbox_messages.sql:104` says a second enqueue for one domain fact is "a
    // no-op rather than a double delivery". It is not: there is no ON CONFLICT on this
    // path and the unique key raises. The behaviour is deliberate (a transactional
    // producer cannot retry an enqueue on its own, so a conflict means two domain writes
    // claimed one fact) and it is exactly why a producer that DOES retry, like the logout
    // explode, must use `enqueue_all` instead. The shipped comment is not edited; this
    // assertion is where the truth is kept.
    let again = outbox
        .enqueue(&env, &delivery("ses_1:cli_a", "https://a.example/bc"))
        .await;
    assert!(
        again.is_err(),
        "the plain enqueue RAISES on a duplicate key, whatever 0099's comment says"
    );
    assert_eq!(
        pending_count(&db, scope, BACKCHANNEL_LOGOUT_CONSUMER).await,
        1
    );
}

#[tokio::test]
async fn the_logout_fan_out_is_isolated_across_tenants() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;

    db.store()
        .scoped(scope_a)
        .outbox()
        .enqueue_all(&env, &[delivery("ses_1:cli_a", "https://a.example/bc")])
        .await
        .expect("enqueue in A");

    assert_eq!(
        pending_count(&db, scope_a, BACKCHANNEL_LOGOUT_CONSUMER).await,
        1,
        "A sees its own delivery"
    );
    assert!(
        db.store()
            .scoped(scope_b)
            .outbox()
            .claim(
                &env,
                BACKCHANNEL_LOGOUT_CONSUMER,
                Duration::from_secs(60),
                100
            )
            .await
            .expect("B claim")
            .is_empty(),
        "B never claims A's deliveries"
    );

    // A raw B-scoped SELECT sees nothing: RLS enforces the boundary beneath the repo.
    let mut tx = db.app_pool().begin().await.expect("begin B tx");
    bind_scope(
        &mut tx,
        &scope_b.tenant().to_string(),
        &scope_b.environment().to_string(),
    )
    .await;
    let visible: i64 = sqlx::query("SELECT count(*) AS n FROM outbox_messages WHERE consumer = $1")
        .bind(BACKCHANNEL_LOGOUT_CONSUMER)
        .fetch_one(&mut *tx)
        .await
        .expect("count")
        .get("n");
    assert_eq!(
        visible, 0,
        "RLS hides A's deliveries from a B-scoped connection"
    );
    let _ = tx.rollback().await;
}

#[tokio::test]
async fn ending_a_session_still_enqueues_exactly_one_session_ended_message() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = UserId::generate(&env, &scope).to_string();
    let session = create_session(&db, &env, scope, &subject).await;
    create_participant(&db, &env, scope, &session, Some("https://a.example/bc")).await;

    // The producer side is untouched by #104's second stage: one terminal session end
    // still enqueues ONE session_ended message, and the fan-out is what consumes it.
    end_session(&db, &env, scope, &session).await;
    let pending = db
        .store()
        .scoped(scope)
        .outbox()
        .pending(SESSION_ENDED_CONSUMER, 100)
        .await
        .expect("pending session_ended");
    assert_eq!(pending.len(), 1);
    assert_eq!(
        pending[0].idempotency_key,
        session.to_string(),
        "the session id is the dedup handle, so a re-end cannot double the fan-out"
    );
    assert_eq!(
        pending_count(&db, scope, BACKCHANNEL_LOGOUT_CONSUMER).await,
        0,
        "nothing is delivered until the explode consumer runs"
    );
}

/// Bind the transaction-local row-level-security scope variables, exactly as the
/// repository does, so a raw adversarial query runs under the same scope.
async fn bind_scope(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant: &str,
    environment: &str,
) {
    sqlx::query("SELECT set_config('ironauth.tenant_id', $1, true)")
        .bind(tenant)
        .execute(&mut **tx)
        .await
        .expect("bind tenant scope");
    sqlx::query("SELECT set_config('ironauth.environment_id', $1, true)")
        .bind(environment)
        .execute(&mut **tx)
        .await
        .expect("bind environment scope");
}
