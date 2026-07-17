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
