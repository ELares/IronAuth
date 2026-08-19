// SPDX-License-Identifier: MIT OR Apache-2.0

//! Credential-abuse defenses at the persistence layer (issue #64), over a real database.
//!
//! Pins the security-critical acceptance criteria of the durable ban registry and the
//! layered failure counters: a ban is per-dimension AND per-PATH, so a `password` ban
//! never governs the `passkey` or `recovery` path (the account-DoS safeguard, Keycloak
//! CVE-2024-1722); the ban subject is envelope-sealed (no plaintext dump); a ban lifts
//! idempotently; a ban auto-expires; and the failure counters SURVIVE a restart (a fresh
//! Store over the same database still sees the accumulated count).

use std::time::SystemTime;

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{AbuseSubject, AuthPath, CorrelationId, Scope, Store};
use sqlx::Row;

/// The current clock-seam time in microseconds since the Unix epoch.
fn now_micros(env: &Env) -> i64 {
    i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("after epoch")
            .as_micros(),
    )
    .expect("fits i64")
}

/// Place a ban through the audited store repository.
async fn place_ban(
    store: &Store,
    env: &Env,
    scope: Scope,
    subject: &AbuseSubject,
    path: AuthPath,
    expires_at: Option<i64>,
) {
    let id = ironauth_store::AbuseBanId::generate(env, &scope);
    store
        .scoped(scope)
        .acting(test_actor(), CorrelationId::generate(env))
        .abuse()
        .ban(
            env,
            ironauth_store::NewBan {
                id: &id,
                subject,
                auth_path: path,
                reason: "test ban",
                expires_at_unix_micros: expires_at,
            },
            now_micros(env),
            None,
        )
        .await
        .expect("place ban");
}

/// A fixed service actor for the audited writes.
fn test_actor() -> ironauth_store::ActorRef {
    ironauth_store::ActorRef::service(ironauth_store::ServiceId::from_seed_bytes([9_u8; 16]))
}

#[tokio::test]
async fn a_password_ban_never_governs_the_passkey_or_recovery_path() {
    // The account-DoS safeguard (issue #64): a ban placed on the password path must be
    // invisible to the passkey and recovery paths, so failed-password spray can never
    // lock the legitimate owner out of every path.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x64);
    let scope = db.seed_scope(&env).await;
    let subject = AbuseSubject::identifier("victim@example.test");

    place_ban(db.store(), &env, scope, &subject, AuthPath::Password, None).await;

    let now = now_micros(&env);
    let subjects = [subject.clone()];
    // The password path IS banned.
    assert!(
        db.store()
            .scoped(scope)
            .abuse()
            .active_ban(&subjects, AuthPath::Password, now)
            .await
            .expect("ban check")
            .is_some(),
        "the password path is banned"
    );
    // The passkey and recovery paths are NOT: they are governed independently.
    for path in [AuthPath::Passkey, AuthPath::Recovery] {
        assert!(
            db.store()
                .scoped(scope)
                .abuse()
                .active_ban(&subjects, path, now)
                .await
                .expect("ban check")
                .is_none(),
            "a password ban must not govern the {path:?} path"
        );
    }
}

#[tokio::test]
async fn ban_round_trips_lists_and_lifts_idempotently() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x65);
    let scope = db.seed_scope(&env).await;
    let subject = AbuseSubject::ip("203.0.113.7");

    place_ban(db.store(), &env, scope, &subject, AuthPath::Password, None).await;

    // The listing OPENS the sealed subject for the operator.
    let bans = db
        .store()
        .scoped(scope)
        .abuse()
        .list_active(now_micros(&env))
        .await
        .expect("list");
    assert_eq!(bans.len(), 1);
    assert_eq!(bans[0].subject, "203.0.113.7");
    assert_eq!(bans[0].auth_path, AuthPath::Password);

    // The stored subject is SEALED (no plaintext in the row).
    let sealed: Vec<u8> = sqlx::query("SELECT subject_sealed FROM abuse_bans LIMIT 1")
        .fetch_one(db.owner_pool())
        .await
        .expect("row")
        .get("subject_sealed");
    assert!(
        !sealed.windows(11).any(|w| w == b"203.0.113.7"),
        "the ban subject must be sealed, never plaintext"
    );

    // Lift removes it, and a repeat lift is idempotent (false, no error).
    let lifted = db
        .store()
        .scoped(scope)
        .acting(test_actor(), CorrelationId::generate(&env))
        .abuse()
        .lift(&env, &subject, AuthPath::Password, None)
        .await
        .expect("lift");
    assert!(lifted, "the first lift removed the ban");
    let again = db
        .store()
        .scoped(scope)
        .acting(test_actor(), CorrelationId::generate(&env))
        .abuse()
        .lift(&env, &subject, AuthPath::Password, None)
        .await
        .expect("second lift");
    assert!(!again, "a repeat lift is idempotent");
    assert!(
        db.store()
            .scoped(scope)
            .abuse()
            .list_active(now_micros(&env))
            .await
            .expect("list")
            .is_empty()
    );
}

#[tokio::test]
async fn an_expired_ban_is_neither_active_nor_listed() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x66);
    let scope = db.seed_scope(&env).await;
    let subject = AbuseSubject::account("usr_example");
    // Expires one second in the "past" relative to the check below.
    let expires = now_micros(&env).saturating_add(1_000_000);
    place_ban(
        db.store(),
        &env,
        scope,
        &subject,
        AuthPath::Password,
        Some(expires),
    )
    .await;

    let after_expiry = expires.saturating_add(1_000_000);
    let subjects = [subject];
    assert!(
        db.store()
            .scoped(scope)
            .abuse()
            .active_ban(&subjects, AuthPath::Password, after_expiry)
            .await
            .expect("ban check")
            .is_none(),
        "an expired ban is not active"
    );
    assert!(
        db.store()
            .scoped(scope)
            .abuse()
            .list_active(after_expiry)
            .await
            .expect("list")
            .is_empty(),
        "an expired ban is not listed"
    );
}

#[tokio::test]
async fn failure_counters_survive_a_restart() {
    // Persistence across a simulated restart (issue #64): the durable failure counters
    // reuse dcr_rate_counters, so a fresh Store over the SAME database still sees the
    // accumulated count.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x67);
    let scope = db.seed_scope(&env).await;
    let subject = AbuseSubject::identifier("spray@example.test");
    let window = 300;
    let now = now_micros(&env);

    // Record three failures on the password path through the first Store instance.
    for _ in 0..3 {
        db.store()
            .scoped(scope)
            .abuse()
            .record_failure(&subject, AuthPath::Password, window, now)
            .await
            .expect("record");
    }

    // A NEW Store over the same database (the "restart") still sees the count.
    let restarted = db.restart_app_store().await;
    let count = restarted
        .scoped(scope)
        .abuse()
        .failure_count(&subject, AuthPath::Password, window, now)
        .await
        .expect("count");
    assert_eq!(count, 3, "the failure count survived the restart");

    // And the count is PER-PATH: the recovery path is untouched.
    let recovery = restarted
        .scoped(scope)
        .abuse()
        .failure_count(&subject, AuthPath::Recovery, window, now)
        .await
        .expect("count");
    assert_eq!(recovery, 0, "the recovery path counter is independent");
}

#[tokio::test]
async fn a_ban_survives_a_restart() {
    // A durable ban is authoritative in Postgres, so a fresh Store over the same database
    // (a simulated node restart) still sees it active (issue #64 INFO-8).
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x68);
    let scope = db.seed_scope(&env).await;
    let subject = AbuseSubject::account("usr_persisted");

    place_ban(db.store(), &env, scope, &subject, AuthPath::Password, None).await;

    // Drop the original Store and re-open over the same database.
    let restarted = db.restart_app_store().await;
    let subjects = [subject];
    assert!(
        restarted
            .scoped(scope)
            .abuse()
            .active_ban(&subjects, AuthPath::Password, now_micros(&env))
            .await
            .expect("ban check")
            .is_some(),
        "the ban must survive a restart (it is authoritative in Postgres)"
    );
}

#[tokio::test]
async fn clearing_a_failure_counter_relaxes_only_that_path() {
    // A successful auth CLEARS the failure counter for its path (issue #64 LOW-6), and the
    // clear is per-PATH: it never bleeds onto another path's counter.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x69);
    let scope = db.seed_scope(&env).await;
    let subject = AbuseSubject::identifier("fumbler@example.test");
    let window = 300;
    let now = now_micros(&env);

    for _ in 0..4 {
        db.store()
            .scoped(scope)
            .abuse()
            .record_failure(&subject, AuthPath::Password, window, now)
            .await
            .expect("record password failure");
    }
    db.store()
        .scoped(scope)
        .abuse()
        .record_failure(&subject, AuthPath::Recovery, window, now)
        .await
        .expect("record recovery failure");

    // Clear the PASSWORD path only.
    db.store()
        .scoped(scope)
        .abuse()
        .clear_failures(&subject, AuthPath::Password)
        .await
        .expect("clear password counter");

    assert_eq!(
        db.store()
            .scoped(scope)
            .abuse()
            .failure_count(&subject, AuthPath::Password, window, now)
            .await
            .expect("count"),
        0,
        "the password counter is cleared"
    );
    assert_eq!(
        db.store()
            .scoped(scope)
            .abuse()
            .failure_count(&subject, AuthPath::Recovery, window, now)
            .await
            .expect("count"),
        1,
        "the recovery counter is untouched by clearing the password path"
    );
}

#[tokio::test]
async fn the_fail_closed_security_cells_deny_when_the_master_key_is_missing() {
    // The security (fail-CLOSED) abuse cells surface their backend failure when the envelope
    // master key is missing (issue #64 MEDIUM-5): the per-identifier failure counter (read
    // and write), the ban check, and the counter clear all ERROR rather than silently
    // admitting, so the caller (`OidcState::regulate_before`) denies the attempt. This
    // simulates the "missing master key" backend failure for each fail-closed cell.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x6a);
    let scope = db.seed_scope(&env).await;

    // A store over the SAME database but with NO master key wired: the identifier-keyed and
    // ban paths fail closed.
    let no_master = Store::from_pool(db.app_pool().clone());
    let subject = AbuseSubject::identifier("victim@example.test");
    let window = 300;
    let now = now_micros(&env);

    // The per-identifier failure counter INCREMENT fails closed (an identifier subject
    // cannot be blind-indexed without the master key).
    assert!(
        no_master
            .scoped(scope)
            .abuse()
            .record_failure(&subject, AuthPath::Password, window, now)
            .await
            .is_err(),
        "the per-identifier counter increment must fail closed without a master key"
    );
    // The per-identifier failure counter READ fails closed.
    assert!(
        no_master
            .scoped(scope)
            .abuse()
            .failure_count(&subject, AuthPath::Password, window, now)
            .await
            .is_err(),
        "the per-identifier counter read must fail closed without a master key"
    );
    // The durable ban check fails closed (the subjects are blind-indexed for the lookup).
    let subjects = [subject.clone()];
    assert!(
        no_master
            .scoped(scope)
            .abuse()
            .active_ban(&subjects, AuthPath::Password, now)
            .await
            .is_err(),
        "the ban check must fail closed without a master key"
    );
    // The counter clear (on a successful auth) fails closed too.
    assert!(
        no_master
            .scoped(scope)
            .abuse()
            .clear_failures(&subject, AuthPath::Password)
            .await
            .is_err(),
        "the per-identifier counter clear must fail closed without a master key"
    );
}

#[tokio::test]
async fn expired_pow_challenges_are_reclaimed_on_the_issue_path_and_live_ones_are_kept() {
    // The bounded request-path reclaim (issue #80 LOW-3): the DELETE grant added to
    // migration 0057 lets the issue path clear its OWN already-expired challenge rows, so
    // the table cannot grow without bound. A LIVE (unexpired) challenge is never reclaimed.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x80);
    let scope = db.seed_scope(&env).await;
    let store = db.store();

    // One challenge that expires 1ms after the epoch (already expired) and one that expires
    // far in the future (still live).
    let expired_id = ironauth_store::PowChallengeId::generate(&env, &scope);
    let live_id = ironauth_store::PowChallengeId::generate(&env, &scope);
    store
        .scoped(scope)
        .pow_challenges()
        .mint(
            &expired_id,
            &ironauth_store::NewPowChallenge {
                challenge: b"expired-challenge",
                difficulty_bits: 8,
                context_hash: b"ctx-a",
                expires_at_micros: 1_000,
            },
        )
        .await
        .expect("mint expired");
    store
        .scoped(scope)
        .pow_challenges()
        .mint(
            &live_id,
            &ironauth_store::NewPowChallenge {
                challenge: b"live-challenge",
                difficulty_bits: 8,
                context_hash: b"ctx-b",
                expires_at_micros: 10_000_000_000,
            },
        )
        .await
        .expect("mint live");

    // Reclaiming at 2s past the epoch removes exactly the expired row (the live one is not
    // yet expired), and a second reclaim at the same instant is a no-op (bounded, idempotent).
    let reclaimed = store
        .scoped(scope)
        .pow_challenges()
        .reclaim_expired(2_000_000, 32)
        .await
        .expect("reclaim");
    assert_eq!(reclaimed, 1, "exactly the expired challenge is reclaimed");
    let again = store
        .scoped(scope)
        .pow_challenges()
        .reclaim_expired(2_000_000, 32)
        .await
        .expect("reclaim again");
    assert_eq!(
        again, 0,
        "nothing else is expired yet, so the reclaim is a no-op"
    );

    // Only once the live challenge's own expiry passes is it reclaimable, proving it was
    // KEPT until then.
    let live_reclaimed = store
        .scoped(scope)
        .pow_challenges()
        .reclaim_expired(20_000_000_000, 32)
        .await
        .expect("reclaim live");
    assert_eq!(
        live_reclaimed, 1,
        "the previously-live challenge is reclaimed only after it expires"
    );
}

/// Claim and complete everything queued for the webhook fan-out in this scope.
async fn queued_events(db: &TestDatabase, env: &Env, scope: Scope) -> Vec<serde_json::Value> {
    let claimed = db
        .store()
        .scoped(scope)
        .outbox()
        .claim(
            env,
            ironauth_store::WEBHOOK_EVENT_CONSUMER,
            std::time::Duration::from_secs(30),
            100,
        )
        .await
        .expect("claim");
    for message in &claimed {
        db.store()
            .scoped(scope)
            .outbox()
            .complete(env, message)
            .await
            .expect("complete");
    }
    claimed.into_iter().map(|message| message.payload).collect()
}

/// Placing and lifting a ban emit distinct types, carrying no subject and no reason, and a
/// lift that matched nothing announces nothing.
///
/// A ban is a security mutation, so a consumer mirroring blocks needs both halves and must
/// not read a lift as a no-op. What it must NOT get is the subject: an IP, a canonical login
/// identifier, or an account, the same class the identifier events already withhold, and an
/// event reaches a wider audience than the management surface that returns it. The operator's
/// free-text reason is withheld for the same reason.
///
/// The create carries the minted id; the LIFT does not, because a lift is addressed by
/// (subject, path) and its producer never learns which row matched. The test asserts that
/// absence, so a later change that reads the id back out of the write fails here.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn placing_and_lifting_a_ban_emit_distinct_types() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = AbuseSubject {
        kind: ironauth_store::AbuseSubjectKind::Identifier,
        value: "ada@events.test".to_owned(),
    };
    let id = ironauth_store::AbuseBanId::generate(&env, &scope);
    let expires_at = now_micros(&env) + 3_600_000_000;

    let created = ironauth_store::event_catalog::envelope(
        "evt_ban_created",
        "ban.created",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        1,
        &serde_json::json!({
            "ban_id": id.to_string(),
            "subject_kind": "identifier",
            "auth_path": "password",
            "expires_at_unix_ms": expires_at / 1000,
        }),
    )
    .expect("ban.created is registered");

    db.store()
        .scoped(scope)
        .acting(test_actor(), CorrelationId::generate(&env))
        .abuse()
        .ban_with_event(
            &env,
            ironauth_store::NewBan {
                id: &id,
                subject: &subject,
                auth_path: AuthPath::Password,
                reason: "operator suspects credential stuffing from ada@events.test",
                expires_at_unix_micros: Some(expires_at),
            },
            now_micros(&env),
            None,
            Some(&ironauth_store::DomainEvent {
                id: "evt_ban_created",
                subject: "identifier:password",
                envelope: &created,
            }),
        )
        .await
        .expect("place ban");

    let placed = queued_events(&db, &env, scope).await;
    assert_eq!(placed.len(), 1, "placing announced {placed:?}");
    assert_eq!(placed[0]["type"], "ban.created");
    assert_eq!(placed[0]["payload"]["ban_id"], id.to_string());
    assert_eq!(placed[0]["payload"]["subject_kind"], "identifier");
    assert_eq!(placed[0]["payload"]["auth_path"], "password");
    let rendered = serde_json::to_string(&placed[0]).expect("json");
    assert!(
        !rendered.contains("ada@events.test"),
        "the ban SUBJECT reached the wire: {rendered}"
    );
    assert!(
        !rendered.contains("credential stuffing"),
        "the operator's free-text reason reached the wire: {rendered}"
    );

    let lifted_envelope = ironauth_store::event_catalog::envelope(
        "evt_ban_lifted",
        "ban.lifted",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        2,
        &serde_json::json!({ "subject_kind": "identifier", "auth_path": "password" }),
    )
    .expect("ban.lifted is registered");

    let lifted = db
        .store()
        .scoped(scope)
        .acting(test_actor(), CorrelationId::generate(&env))
        .abuse()
        .lift_with_event(
            &env,
            &subject,
            AuthPath::Password,
            None,
            Some(&ironauth_store::DomainEvent {
                id: "evt_ban_lifted",
                subject: "identifier:password",
                envelope: &lifted_envelope,
            }),
        )
        .await
        .expect("lift");
    assert!(lifted, "the first lift removed the ban");

    let released = queued_events(&db, &env, scope).await;
    assert_eq!(released.len(), 1, "lifting announced {released:?}");
    assert_eq!(
        released[0]["type"], "ban.lifted",
        "a lift announced as a placement, or not at all, leaves a consumer blocking a \
         subject an operator released"
    );
    assert!(
        released[0]["payload"].get("ban_id").is_none(),
        "a lift is addressed by (subject, path) and never learns which row matched, so an id \
         here could only have been read back out of the write: {released:?}"
    );

    // The no-op branch returns before the audited write the enqueue lives inside, so a
    // repeat lift announces nothing: a consumer must not see a release that did not happen.
    let repeat_envelope = ironauth_store::event_catalog::envelope(
        "evt_ban_lifted_again",
        "ban.lifted",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        3,
        &serde_json::json!({ "subject_kind": "identifier", "auth_path": "password" }),
    )
    .expect("ban.lifted is registered");
    let again = db
        .store()
        .scoped(scope)
        .acting(test_actor(), CorrelationId::generate(&env))
        .abuse()
        .lift_with_event(
            &env,
            &subject,
            AuthPath::Password,
            None,
            Some(&ironauth_store::DomainEvent {
                id: "evt_ban_lifted_again",
                subject: "identifier:password",
                envelope: &repeat_envelope,
            }),
        )
        .await
        .expect("repeat lift");
    assert!(!again, "the repeat lift matched nothing");
    let quiet = queued_events(&db, &env, scope).await;
    assert!(
        quiet.is_empty(),
        "a lift that matched nothing must announce nothing: {quiet:?}"
    );
}

/// A producer that emits an OFF-SCHEMA payload fails the test that exercised it
/// (issue #108 criterion 1).
///
/// The fan-out validates every event before delivery, which is the right place at run time
/// but the wrong place to LEARN about it: its failure is a log line and a permanent consumer
/// error, discovered by whoever watches deliveries, long after the producer that built the
/// envelope went out of scope.
///
/// Under the `testing` feature the same check runs inside the producer's own transaction, so
/// this is what the criterion means by "fails the build". The envelope below declares a
/// registered type and then violates its schema -- `ban.created` requires `ban_id`, and this
/// omits it -- which is exactly the shape a producer edited without its schema produces.
#[tokio::test]
#[should_panic(expected = "does not validate against the registry")]
async fn a_producer_emitting_an_off_schema_payload_fails_the_test_that_exercised_it() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = AbuseSubject {
        kind: ironauth_store::AbuseSubjectKind::Identifier,
        value: "schema@events.test".to_owned(),
    };
    let id = ironauth_store::AbuseBanId::generate(&env, &scope);

    // Built by hand rather than through `event_catalog::envelope`, because that constructor
    // VALIDATES and would refuse this -- which is the point: the constructor is the guard a
    // producer is supposed to go through, and this test is about what happens when an
    // envelope reaches the enqueue without having passed one.
    let invalid = serde_json::json!({
        "id": "evt_off_schema",
        "type": "ban.created",
        "payload_schema_version": 1,
        "occurred_at_unix_ms": 1,
        "tenant_id": scope.tenant().to_string(),
        "environment_id": scope.environment().to_string(),
        // `ban_id` is REQUIRED by the registered schema and is missing.
        "payload": { "subject_kind": "identifier", "auth_path": "password" },
    });

    db.store()
        .scoped(scope)
        .acting(test_actor(), CorrelationId::generate(&env))
        .abuse()
        .ban_with_event(
            &env,
            ironauth_store::NewBan {
                id: &id,
                subject: &subject,
                auth_path: AuthPath::Password,
                reason: "schema check",
                expires_at_unix_micros: None,
            },
            now_micros(&env),
            None,
            Some(&ironauth_store::DomainEvent {
                id: "evt_off_schema",
                subject: "identifier:password",
                envelope: &invalid,
            }),
        )
        .await
        .expect("unreachable: the enqueue panics before this resolves");
}

/// The DIRECT appender is covered by the same guard (issue #108 criterion 1).
///
/// The sibling above drives `enqueue_domain_event`, the path a producer takes when it rides
/// a domain write. That is where the assertion originally lived, and there it covered ten of
/// eleven producers. `OutboxRepo::append_event` is the eleventh: the documented path for a
/// producer with no domain write to ride (a scheduled job, an operator-triggered publish),
/// and it went straight to the insert. A guard that covers all but one producer is a guard
/// the remaining one will eventually find, which is what the usage publisher did.
///
/// So the check now sits at the INSERT rather than at one producer, and this test is what
/// makes that true rather than intended. There are two inserts, not one -- the
/// conflict-tolerant path has its own -- and the sibling below covers the other.
#[tokio::test]
#[should_panic(expected = "does not validate against the registry")]
async fn the_direct_appender_is_covered_by_the_emit_time_schema_guard() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // Same shape as the sibling: a REGISTERED type whose payload violates its schema, built
    // by hand because `event_catalog::envelope` would refuse it.
    let invalid = serde_json::json!({
        "id": "evt_direct_off_schema",
        "type": "ban.created",
        "payload_schema_version": 1,
        "occurred_at_unix_ms": 1,
        "tenant_id": scope.tenant().to_string(),
        "environment_id": scope.environment().to_string(),
        "payload": { "subject_kind": "identifier", "auth_path": "password" },
    });

    db.store()
        .scoped(scope)
        .outbox()
        .append_event(
            &env,
            &ironauth_store::NewOutboxMessage {
                consumer: ironauth_store::WEBHOOK_EVENT_CONSUMER,
                idempotency_key: "evt_direct_off_schema",
                ordering_key: "identifier:password",
                payload: invalid,
            },
        )
        .await
        .expect("unreachable: the append panics before this resolves");
}

/// The guard is scoped to the EVENT feed, and that scoping is deliberate.
///
/// A message on `WEBHOOK_DELIVERY_CONSUMER` is a delivery instruction, not an event: it
/// carries a different payload shape that the catalog does not describe and must not be
/// measured against. Without this test the scoping is an untested condition, and the
/// cheapest wrong way to write the guard -- drop the consumer check and validate every
/// outbox row -- would break every delivery in the system while the two tests above stayed
/// green.
#[tokio::test]
async fn a_delivery_message_is_not_measured_against_the_event_registry() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // Not an event envelope at all, and correctly so.
    let delivery = serde_json::json!({ "endpoint": "whe_x", "attempt": 1 });

    db.store()
        .scoped(scope)
        .outbox()
        .append_event(
            &env,
            &ironauth_store::NewOutboxMessage {
                consumer: ironauth_store::WEBHOOK_DELIVERY_CONSUMER,
                idempotency_key: "dlv_not_an_event",
                ordering_key: "whe_x",
                payload: delivery,
            },
        )
        .await
        .expect("a delivery message is not an event and must append unchallenged");
}

/// The CONFLICT-TOLERANT insert is covered by the same guard too (issue #108 criterion 1).
///
/// `OutboxRepo::enqueue_all` writes through `enqueue_outbox_in_tx_ignoring_conflict`, which
/// carries its own `INSERT` and so did not reach the assertion when it moved down from
/// `enqueue_domain_event`. Review put an unregistered type through it and watched the row
/// land with no panic, which made "the single statement every event-feed row passes through"
/// false by exactly one statement -- the same shape as the defect the move was fixing, one
/// function over.
///
/// No live hole existed: both production callers of `enqueue_all` use
/// `WEBHOOK_DELIVERY_CONSUMER` and `BACKCHANNEL_LOGOUT_CONSUMER`. But `enqueue_all` is the
/// shape a fan-out producer is documented to use, so the next one would have found it, and a
/// claim asserted in three places that outlive this change had better be true.
#[tokio::test]
#[should_panic(expected = "does not validate against the registry")]
async fn the_conflict_tolerant_insert_is_covered_by_the_emit_time_schema_guard() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let invalid = serde_json::json!({
        "id": "evt_enqueue_all_off_schema",
        "type": "ban.created",
        "payload_schema_version": 1,
        "occurred_at_unix_ms": 1,
        "tenant_id": scope.tenant().to_string(),
        "environment_id": scope.environment().to_string(),
        "payload": { "subject_kind": "identifier", "auth_path": "password" },
    });

    db.store()
        .scoped(scope)
        .outbox()
        .enqueue_all(
            &env,
            &[ironauth_store::NewOutboxMessage {
                consumer: ironauth_store::WEBHOOK_EVENT_CONSUMER,
                idempotency_key: "evt_enqueue_all_off_schema",
                ordering_key: "identifier:password",
                payload: invalid,
            }],
        )
        .await
        .expect("unreachable: the enqueue panics before this resolves");
}
