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
        .lift(&env, &subject, AuthPath::Password)
        .await
        .expect("lift");
    assert!(lifted, "the first lift removed the ban");
    let again = db
        .store()
        .scoped(scope)
        .acting(test_actor(), CorrelationId::generate(&env))
        .abuse()
        .lift(&env, &subject, AuthPath::Password)
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
