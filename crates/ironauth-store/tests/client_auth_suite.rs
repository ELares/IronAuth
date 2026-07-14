// SPDX-License-Identifier: MIT OR Apache-2.0

//! The JWT-assertion client-authentication store surfaces (issue #25), over a
//! real database (`DATABASE_URL`).
//!
//! Proves the cross-node single-use `jti` replay cache (two independent store
//! handles against one database, the second use rejected), the safe TTL prune
//! (an expired jti is reclaimed only after its last-replayable instant, never
//! opening a window for a still-valid assertion), the cross-scope isolation of
//! both new tables, and that the out-of-band diagnostics sink records and reads
//! back a failure's rich detail.

use std::time::Duration;

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ClientAuthDiagnosticReason, CorrelationId, JtiOutcome, NewClientAuthDiagnostic,
    NewJwtAuthClient, Scope, Store, StoreError,
};

/// A far-future expiry (year 2100) in epoch microseconds, so a recorded jti is
/// never pruned before a test means it to be.
const FAR_FUTURE_MICROS: i64 = 4_102_444_800_000_000;

#[tokio::test]
async fn a_jti_is_single_use_across_two_store_handles_on_one_database() {
    // Two store handles over the SAME database simulate two server nodes: the
    // second use of a jti must be rejected by the shared unique constraint, not by
    // any in-memory state.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x25);
    let scope = db.seed_scope(&env).await;

    let node_a: Store = db.store().clone();
    let node_b: Store = Store::from_pool(db.app_pool().clone());

    // Node A records the jti first: a clean single use.
    let first = node_a
        .scoped(scope)
        .client_assertion_jtis()
        .record(&env, "cli_x", "jti-shared", FAR_FUTURE_MICROS)
        .await
        .expect("record on node A");
    assert_eq!(first, JtiOutcome::Recorded);

    // Node B replays the SAME jti: the shared database rejects it.
    let replay = node_b
        .scoped(scope)
        .client_assertion_jtis()
        .record(&env, "cli_x", "jti-shared", FAR_FUTURE_MICROS)
        .await
        .expect("record on node B");
    assert_eq!(
        replay,
        JtiOutcome::Replayed,
        "a second node cannot reuse a jti"
    );

    // A different jti, and the same jti for a DIFFERENT client, are both fresh
    // (jti uniqueness is per client, per RFC 7523).
    assert_eq!(
        node_b
            .scoped(scope)
            .client_assertion_jtis()
            .record(&env, "cli_x", "jti-other", FAR_FUTURE_MICROS)
            .await
            .expect("distinct jti"),
        JtiOutcome::Recorded
    );
    assert_eq!(
        node_a
            .scoped(scope)
            .client_assertion_jtis()
            .record(&env, "cli_y", "jti-shared", FAR_FUTURE_MICROS)
            .await
            .expect("same jti, different client"),
        JtiOutcome::Recorded
    );
}

#[tokio::test]
async fn a_replayed_jti_in_another_scope_is_not_a_conflict() {
    // The replay cache is RLS-scoped: the same jti in a different (tenant,
    // environment) is a fresh, independent single use, never a cross-scope clash.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x26);
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;

    assert_eq!(
        record(db.store(), &env, scope_a, "cli_x", "jti-1").await,
        JtiOutcome::Recorded
    );
    assert_eq!(
        record(db.store(), &env, scope_a, "cli_x", "jti-1").await,
        JtiOutcome::Replayed,
        "same scope replays"
    );
    assert_eq!(
        record(db.store(), &env, scope_b, "cli_x", "jti-1").await,
        JtiOutcome::Recorded,
        "another scope is independent"
    );
}

#[tokio::test]
async fn the_prune_reclaims_a_jti_only_after_its_replayable_window_has_passed() {
    // A jti stays single-use while its assertion could still be replayed, and is
    // reclaimed only once its stored expiry (assertion exp + skew) has passed, so
    // pruning never opens a window for a still-valid assertion.
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x27);
    let scope = db.seed_scope(&env).await;

    // Record jti-A expiring one second from the epoch (the clock's start).
    let expires = 1_000_000_i64;
    assert_eq!(
        record_expiring(db.store(), &env, scope, "cli_x", "jti-A", expires).await,
        JtiOutcome::Recorded
    );
    // While still within its window, a replay is rejected.
    assert_eq!(
        record_expiring(db.store(), &env, scope, "cli_x", "jti-A", expires).await,
        JtiOutcome::Replayed,
        "still within the replayable window"
    );

    // Advance the clock past the window. Recording ANY jti now prunes the expired
    // jti-A first, so jti-A becomes re-insertable (its assertion is itself expired
    // by now and would be rejected by verification anyway).
    clock.advance(Duration::from_secs(5));
    assert_eq!(
        record_expiring(db.store(), &env, scope, "cli_x", "jti-B", FAR_FUTURE_MICROS).await,
        JtiOutcome::Recorded
    );
    assert_eq!(
        record_expiring(db.store(), &env, scope, "cli_x", "jti-A", FAR_FUTURE_MICROS).await,
        JtiOutcome::Recorded,
        "an expired jti is reclaimed by the prune"
    );
}

#[tokio::test]
async fn a_client_auth_diagnostic_is_recorded_and_read_back_within_scope() {
    // The out-of-band diagnostics sink records a failure's rich detail (method,
    // reason, key id, alg) and reads it back within scope; another scope sees none.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x28);
    let scope = db.seed_scope(&env).await;
    let other = db.seed_scope(&env).await;

    db.store()
        .scoped(scope)
        .client_auth_diagnostics()
        .record(
            &env,
            NewClientAuthDiagnostic {
                client_id: "cli_diag",
                auth_method: "private_key_jwt",
                reason: ClientAuthDiagnosticReason::AssertionInvalid,
                key_id: Some("k9"),
                signing_alg: Some("ES256"),
            },
        )
        .await
        .expect("record diagnostic");

    let rows = db
        .store()
        .scoped(scope)
        .client_auth_diagnostics()
        .for_client("cli_diag")
        .await
        .expect("read diagnostics");
    assert_eq!(rows.len(), 1, "one diagnostic recorded");
    let row = &rows[0];
    assert_eq!(row.auth_method, "private_key_jwt");
    assert_eq!(row.failure_reason, "assertion_invalid");
    assert_eq!(row.key_id.as_deref(), Some("k9"));
    assert_eq!(row.signing_alg.as_deref(), Some("ES256"));

    // Another scope sees nothing (RLS isolation).
    assert!(
        db.store()
            .scoped(other)
            .client_auth_diagnostics()
            .for_client("cli_diag")
            .await
            .expect("read diagnostics in other scope")
            .is_empty(),
        "a diagnostic is isolated to its own scope"
    );
}

#[tokio::test]
async fn the_retention_margin_keeps_a_jti_single_use_across_the_whole_acceptance_second() {
    // FIX (issue #25 review): acceptance (enforce_exp) floors `now` to WHOLE seconds
    // and rejects only once now_secs > exp+skew, so an assertion stays acceptable for
    // the ENTIRE wall-clock second [exp+skew, exp+skew+1). The recorder stores
    // expires_at = (exp+skew+1)*1e6, so the single-use row survives that whole second
    // even though pruning runs at MICROSECOND precision. A bare (exp+skew)*1e6 row
    // would be pruned partway through the second and re-admit the single-use assertion.
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x29);
    let scope = db.seed_scope(&env).await;

    // exp+skew lands on a whole second; the recorder's +1s margin makes expires 101s.
    let exp_plus_skew_secs: i64 = 100;
    let retained_micros = (exp_plus_skew_secs + 1) * 1_000_000;

    // First use at the epoch (now = 0): recorded.
    assert_eq!(
        record_expiring(
            db.store(),
            &env,
            scope,
            "cli_x",
            "jti-window",
            retained_micros
        )
        .await,
        JtiOutcome::Recorded
    );

    // At EXACTLY exp+skew (the last acceptable whole second) the assertion is still
    // acceptable, so a replay must still be caught: the row is NOT pruned yet.
    clock.advance(Duration::from_secs(
        u64::try_from(exp_plus_skew_secs).expect("non-negative"),
    ));
    assert_eq!(
        record_expiring(
            db.store(),
            &env,
            scope,
            "cli_x",
            "jti-window",
            retained_micros
        )
        .await,
        JtiOutcome::Replayed,
        "still replayable at exp+skew"
    );

    // Half a second into that same acceptance second: still replayable.
    clock.advance(Duration::from_millis(500));
    assert_eq!(
        record_expiring(
            db.store(),
            &env,
            scope,
            "cli_x",
            "jti-window",
            retained_micros
        )
        .await,
        JtiOutcome::Replayed,
        "still replayable at exp+skew+0.5s"
    );

    // At exp+skew+1s (now_secs > exp+skew: the assertion is no longer acceptable) the
    // row is finally pruned, so the jti becomes re-insertable. This is the ONLY point
    // it stops being replay-relevant, and by now verification itself would reject the
    // (expired) assertion anyway.
    clock.advance(Duration::from_millis(500));
    assert_eq!(
        record_expiring(
            db.store(),
            &env,
            scope,
            "cli_x",
            "jti-window",
            retained_micros
        )
        .await,
        JtiOutcome::Recorded,
        "reclaimed exactly at exp+skew+1s"
    );
}

#[tokio::test]
async fn registering_with_both_jwks_and_jwks_uri_is_a_conflict() {
    // The key sources are mutually exclusive (a private_key_jwt client registers keys
    // inline OR by reference, never both): setting both is a caller-facing Conflict,
    // enforced by the database CHECK and mapped from SQLSTATE 23514.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x2A);
    let scope = db.seed_scope(&env).await;

    let result = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .create_jwt_auth(
            &env,
            NewJwtAuthClient {
                display_name: "dual-source client",
                auth_method: "private_key_jwt",
                jwks: Some(r#"{"keys":[]}"#),
                jwks_uri: Some("https://client.test/jwks.json"),
                signing_alg: None,
            },
        )
        .await;
    assert!(
        matches!(result, Err(StoreError::Conflict)),
        "both jwks and jwks_uri is a Conflict: {result:?}"
    );
}

#[tokio::test]
async fn a_keyless_private_key_jwt_registration_is_rejected() {
    // A private_key_jwt client MUST register exactly one key source. A KEYLESS one
    // would register but fail every request silently (no key to verify against), so
    // it is rejected LOUD at registration (the DB CHECK maps to Conflict). The
    // exactly-one-source control still registers cleanly.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x2B);
    let scope = db.seed_scope(&env).await;

    let keyless = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .create_jwt_auth(
            &env,
            NewJwtAuthClient {
                display_name: "keyless client",
                auth_method: "private_key_jwt",
                jwks: None,
                jwks_uri: None,
                signing_alg: None,
            },
        )
        .await;
    assert!(
        matches!(keyless, Err(StoreError::Conflict)),
        "a keyless private_key_jwt registration is rejected: {keyless:?}"
    );

    // Exactly one source (inline jwks) is a valid registration.
    let ok = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .create_jwt_auth(
            &env,
            NewJwtAuthClient {
                display_name: "one-key client",
                auth_method: "private_key_jwt",
                jwks: Some(r#"{"keys":[]}"#),
                jwks_uri: None,
                signing_alg: None,
            },
        )
        .await;
    assert!(ok.is_ok(), "a single-key private_key_jwt registers: {ok:?}");
}

#[tokio::test]
async fn registering_client_secret_jwt_is_rejected_loud() {
    // client_secret_jwt is inert (IronAuth stores no retrievable secret to key the
    // HMAC), so registering a client for it would silently fail every request. The
    // misconfiguration is refused LOUD at registration instead.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x2C);
    let scope = db.seed_scope(&env).await;

    let result = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .create_jwt_auth(
            &env,
            NewJwtAuthClient {
                display_name: "client_secret_jwt client",
                auth_method: "client_secret_jwt",
                jwks: None,
                jwks_uri: None,
                signing_alg: None,
            },
        )
        .await;
    assert!(
        matches!(result, Err(StoreError::Conflict)),
        "client_secret_jwt registration is rejected: {result:?}"
    );
}

/// Record a jti with a far-future expiry in `scope`.
async fn record(db: &Store, env: &Env, scope: Scope, client_id: &str, jti: &str) -> JtiOutcome {
    record_expiring(db, env, scope, client_id, jti, FAR_FUTURE_MICROS).await
}

/// Record a jti with an explicit expiry (epoch microseconds) in `scope`.
async fn record_expiring(
    db: &Store,
    env: &Env,
    scope: Scope,
    client_id: &str,
    jti: &str,
    expires_at_micros: i64,
) -> JtiOutcome {
    db.scoped(scope)
        .client_assertion_jtis()
        .record(env, client_id, jti, expires_at_micros)
        .await
        .expect("record jti")
}
