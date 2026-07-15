// SPDX-License-Identifier: MIT OR Apache-2.0

//! Refresh-token rotation, families, reuse detection, `offline_access`, and the
//! digest-only storage guarantee (issue #21), over a real database
//! (`DATABASE_URL`).
//!
//! These exercise the authoritative single-use, rotation, and reuse gate directly
//! at the store layer (`ActingRefreshRepo`), where the grace-window classification,
//! family revocation, exactly-once reuse event, offline-vs session-bound revocation,
//! and hard-cap/idle expiry all live. The OIDC HTTP surface (rotation policy,
//! `offline_access` consent, consent modes) is proven in
//! `ironauth-oidc/tests/refresh.rs`.

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    AuthorizationCodeId, ClientId, CorrelationId, GrantId, IssueCode, NewRefreshFamily, NewSession,
    RefreshFamilyId, RefreshFamilyOpenOutcome, RefreshRedeem, RefreshRedeemOutcome, RefreshTokenId,
    RotatedRefreshToken, Scope, SessionEndCause, SessionId, refresh_token_digest,
};
use sqlx::Row;

/// A far-future expiry (year 2100) in epoch microseconds: an idle/absolute cap far
/// enough out that the clock advances the reuse and concurrency tests perform never
/// trip it.
const FAR_FUTURE_MICROS: i64 = 4_102_444_800_000_000;

/// Build a refresh token exactly as the mint does (issue #21): the `ira_rt_` prefix,
/// the scope-declaring routing handle (`jti`), a `~` delimiter, and 256 bits from
/// the entropy seam, plus the SHA-256 digest of the WHOLE token.
fn make_refresh_token(env: &Env, scope: Scope) -> (String, RefreshTokenId, String) {
    let jti = RefreshTokenId::generate(env, &scope);
    let mut bytes = [0_u8; 32];
    env.entropy().fill_bytes(&mut bytes);
    let token = format!("ira_rt_{jti}~{}", URL_SAFE_NO_PAD.encode(bytes));
    let digest = refresh_token_digest(&token);
    (token, jti, digest)
}

/// Issue an authorization code and its grant in `scope`, carrying `session_ref`, and
/// return the grant id. The family rooted at this grant reads the `session_ref`, so
/// an RP logout can later revoke a session-bound family.
async fn seed_grant(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    subject: &str,
    session_ref: Option<&SessionId>,
) -> GrantId {
    let code_id = AuthorizationCodeId::generate(env, &scope);
    let grant_id = GrantId::generate(env, &scope);
    let client_id = ClientId::generate(env, &scope);
    let session = session_ref.map(SessionId::to_string);
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .authorization()
        .issue(
            env,
            IssueCode {
                code_id: &code_id,
                grant_id: &grant_id,
                client_id: &client_id,
                redirect_uri: "https://client.test/cb",
                nonce: None,
                code_challenge: None,
                code_challenge_method: None,
                subject,
                oauth_scope: Some("openid"),
                auth_methods: "pwd",
                auth_time_micros: None,
                session_ref: session.as_deref(),
                consent_ref: None,
                claims_request: None,
                granted_resources: &[],
                expires_at_micros: FAR_FUTURE_MICROS,
                created_at_micros: 0,
            },
        )
        .await
        .expect("issue code");
    grant_id
}

/// Create a LIVE session in `scope` for `subject`, so a session-bound family opened
/// against it passes the live-session guard (issue #32). Far-future expiries keep it
/// live until a test explicitly revokes it.
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
            NewSession {
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
        .expect("create session");
    id
}

/// Open a refresh-token family (generation 0) rooted at `grant_id`, returning the
/// family id, the generation-0 token, its jti, and its digest.
#[allow(clippy::too_many_arguments)]
async fn open_family(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    grant_id: &GrantId,
    subject: &str,
    offline: bool,
    idle_expires_at_unix_micros: i64,
    absolute_expires_at_unix_micros: i64,
) -> (RefreshFamilyId, String, RefreshTokenId, String) {
    let family_id = RefreshFamilyId::generate(env, &scope);
    let (token, jti, digest) = make_refresh_token(env, scope);
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .refresh()
        .issue(
            env,
            NewRefreshFamily {
                family_id: &family_id,
                token_jti: &jti,
                token_digest: &digest,
                grant_id,
                subject,
                client_id: "cli_family",
                scope: Some("openid"),
                auth_methods: "pwd",
                offline,
                created_at_unix_micros: 0,
                idle_expires_at_unix_micros,
                absolute_expires_at_unix_micros,
            },
        )
        .await
        .expect("open family");
    (family_id, token, jti, digest)
}

/// Redeem a presented token with a freshly generated successor, returning the
/// outcome and the successor token.
async fn redeem(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    presented: &str,
    rotate: bool,
    grace: Duration,
) -> (RefreshRedeemOutcome, String) {
    let (succ_token, succ_jti, succ_digest) = make_refresh_token(env, scope);
    let outcome = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .refresh()
        .redeem(
            env,
            RefreshRedeem {
                presented_token: presented,
                rotate,
                successor: RotatedRefreshToken {
                    jti: &succ_jti,
                    token_digest: &succ_digest,
                    generation: 1,
                    idle_expires_at_unix_micros: FAR_FUTURE_MICROS,
                },
                access_records: &[],
                opaque: None,
                grace,
            },
        )
        .await
        .expect("redeem");
    (outcome, succ_token)
}

/// Count the audit rows in `scope` whose action equals `action`.
async fn count_action(db: &TestDatabase, scope: Scope, action: &str) -> usize {
    db.store()
        .scoped(scope)
        .audit()
        .list()
        .await
        .expect("list audit")
        .into_iter()
        .filter(|row| row.action == action)
        .count()
}

/// Count the LIVE leaves of `family`: refresh-token rows that are neither rotated
/// (superseded) nor in a revoked family, through the scoped repository read. The
/// rotation invariant (issue #21) is that this is ALWAYS at most one: a family never
/// forks into two sibling live leaves.
async fn count_live_leaves(db: &TestDatabase, scope: Scope, family: &RefreshFamilyId) -> i64 {
    db.store()
        .scoped(scope)
        .refresh()
        .live_leaf_count(family)
        .await
        .expect("count live leaves")
}

#[tokio::test]
async fn reuse_outside_grace_revokes_the_whole_family_and_emits_one_reuse_event() {
    // Acceptance criterion 1: a superseded token presented OUTSIDE the grace window
    // revokes the ENTIRE family and emits the typed reuse event EXACTLY once per
    // incident.
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x21_00_01);
    let scope = db.seed_scope(&env).await;
    let grant = seed_grant(&db, &env, scope, "usr_reuse", None).await;
    let (_family, t0, _jti0, _d0) = open_family(
        &db,
        &env,
        scope,
        &grant,
        "usr_reuse",
        false,
        FAR_FUTURE_MICROS,
        FAR_FUTURE_MICROS,
    )
    .await;

    // Rotate T0 to T1 (frozen clock: rotated_at = now).
    let grace = Duration::from_secs(10);
    let (outcome, t1) = redeem(&db, &env, scope, &t0, true, grace).await;
    assert_eq!(outcome, RefreshRedeemOutcome::Rotated);
    assert!(
        db.store()
            .scoped(scope)
            .refresh()
            .load(&t1)
            .await
            .expect("load")
            .expect("t1 exists")
            .active,
        "the successor is live before the reuse"
    );

    // Advance well past the grace window and present the SUPERSEDED T0 again.
    clock.advance(Duration::from_secs(60));
    let (outcome, _t2) = redeem(&db, &env, scope, &t0, true, grace).await;
    assert_eq!(
        outcome,
        RefreshRedeemOutcome::Reused,
        "a superseded token outside the grace window is a reuse"
    );

    // The WHOLE family is now revoked: the once-live successor no longer resolves as
    // active.
    assert!(
        !db.store()
            .scoped(scope)
            .refresh()
            .load(&t1)
            .await
            .expect("load")
            .expect("t1 still recorded")
            .active,
        "the reuse revoked the whole family, so the successor is inactive too"
    );
    assert_eq!(
        count_action(&db, scope, "refresh_token.reuse").await,
        1,
        "exactly one typed reuse event for the incident"
    );

    // A THIRD presentation of the same token now finds the family already revoked,
    // so it is a plain invalid_grant and writes NO second reuse event: the typed
    // event is emitted exactly once per incident, not once per presentation.
    let (outcome, _t3) = redeem(&db, &env, scope, &t0, true, grace).await;
    assert_eq!(
        outcome,
        RefreshRedeemOutcome::Invalid,
        "a presentation against an already-revoked family is a plain invalid_grant"
    );
    assert_eq!(
        count_action(&db, scope, "refresh_token.reuse").await,
        1,
        "still exactly one reuse event: exactly-once per incident, not per presentation"
    );
}

#[tokio::test]
async fn concurrent_refreshes_within_grace_converge_on_one_live_leaf() {
    // Acceptance criterion 2, hardened (issue #21 adversarial FIX 1): N benign
    // concurrent refreshes of the same token WITHIN the grace window all succeed
    // (no lockout) and none revokes the family, AND the family CONVERGES on EXACTLY
    // ONE live leaf. A within-grace loser mints only a fresh access token, never a
    // second successor leaf, so the family can never fork into two independent,
    // never-reconciled live chains (which would each rotate forever with no reuse
    // signal). This is the store-level proof of the one-live-leaf invariant.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x21_00_02);
    let scope = db.seed_scope(&env).await;
    let grant = seed_grant(&db, &env, scope, "usr_grace", None).await;
    let (family, t0, _jti0, _d0) = open_family(
        &db,
        &env,
        scope,
        &grant,
        "usr_grace",
        false,
        FAR_FUTURE_MICROS,
        FAR_FUTURE_MICROS,
    )
    .await;

    // Exactly one live leaf at issuance (generation 0).
    assert_eq!(
        count_live_leaves(&db, scope, &family).await,
        1,
        "one leaf at issuance"
    );

    let grace = Duration::from_secs(10);
    // First refresh rotates T0 -> T1: T1 is now the family's single live leaf.
    let (first, t1) = redeem(&db, &env, scope, &t0, true, grace).await;
    assert_eq!(first, RefreshRedeemOutcome::Rotated);
    assert_eq!(
        count_live_leaves(&db, scope, &family).await,
        1,
        "after the rotate the successor is the one live leaf"
    );

    // Three more presentations of the SAME (now superseded) T0, all within the
    // (frozen-clock) grace window: each is a benign concurrent refresh that succeeds
    // with a fresh access token but mints NO new refresh leaf, so the live-leaf count
    // stays exactly one every time (convergence, never a fork).
    for _ in 0..3 {
        let (outcome, succ) = redeem(&db, &env, scope, &t0, true, grace).await;
        assert_eq!(
            outcome,
            RefreshRedeemOutcome::RefreshedWithinGrace,
            "a within-grace duplicate is a benign access-only concurrent refresh"
        );
        // The loser's pre-generated successor was NOT recorded: it does not resolve.
        assert!(
            db.store()
                .scoped(scope)
                .refresh()
                .load(&succ)
                .await
                .expect("load")
                .is_none(),
            "a within-grace loser mints no new leaf, so its successor is never recorded"
        );
        assert_eq!(
            count_live_leaves(&db, scope, &family).await,
            1,
            "the family has EXACTLY ONE live leaf after every within-grace refresh"
        );
    }

    // The single live leaf is the winner's successor T1, still active.
    assert!(
        db.store()
            .scoped(scope)
            .refresh()
            .load(&t1)
            .await
            .expect("load")
            .expect("t1 recorded")
            .active,
        "the one live leaf is the winner's successor"
    );
    assert_eq!(
        count_action(&db, scope, "refresh_token.reuse").await,
        0,
        "a within-grace concurrent refresh never revokes the family or emits a reuse event"
    );
}

#[tokio::test]
async fn a_confidential_under_threshold_token_is_not_rotated_and_stays_live() {
    // Acceptance criterion 3 (store mechanism): when the policy says NOT to rotate
    // (a confidential/bound client under the TTL threshold), the presented token is
    // left live and only a fresh access token is issued; a later rotate supersedes it.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x21_00_03);
    let scope = db.seed_scope(&env).await;
    let grant = seed_grant(&db, &env, scope, "usr_norot", None).await;
    let (_family, t0, _jti0, _d0) = open_family(
        &db,
        &env,
        scope,
        &grant,
        "usr_norot",
        false,
        FAR_FUTURE_MICROS,
        FAR_FUTURE_MICROS,
    )
    .await;

    let grace = Duration::from_secs(10);
    let (outcome, _unused) = redeem(&db, &env, scope, &t0, false, grace).await;
    assert_eq!(outcome, RefreshRedeemOutcome::NotRotated);
    let resolved = db
        .store()
        .scoped(scope)
        .refresh()
        .load(&t0)
        .await
        .expect("load")
        .expect("t0 still recorded");
    assert!(resolved.active, "the un-rotated token stays live");
    assert!(!resolved.rotated, "and is not superseded");

    // A subsequent rotate supersedes the same live token cleanly.
    let (outcome, t1) = redeem(&db, &env, scope, &t0, true, grace).await;
    assert_eq!(outcome, RefreshRedeemOutcome::Rotated);
    assert!(
        db.store()
            .scoped(scope)
            .refresh()
            .load(&t1)
            .await
            .expect("load")
            .expect("t1 recorded")
            .active
    );
}

#[tokio::test]
async fn the_family_hard_cap_invalidates_a_refresh_without_a_reuse_event() {
    // Acceptance criterion 3 (hard cap): past the family's absolute lifetime cap no
    // rotation renews it; the refresh is a plain invalid_grant, not a reuse.
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x21_00_04);
    let scope = db.seed_scope(&env).await;
    let grant = seed_grant(&db, &env, scope, "usr_cap", None).await;
    // Absolute cap five seconds out; idle far away so ONLY the cap is exercised.
    let (_family, t0, _jti0, _d0) = open_family(
        &db,
        &env,
        scope,
        &grant,
        "usr_cap",
        false,
        FAR_FUTURE_MICROS,
        5_000_000,
    )
    .await;

    clock.advance(Duration::from_secs(10));
    let (outcome, _unused) = redeem(&db, &env, scope, &t0, true, Duration::from_secs(10)).await;
    assert_eq!(
        outcome,
        RefreshRedeemOutcome::Invalid,
        "past the family hard cap a refresh is invalid_grant"
    );
    assert_eq!(
        count_action(&db, scope, "refresh_token.reuse").await,
        0,
        "an expired-cap refresh is not a reuse"
    );
}

#[tokio::test]
async fn an_idle_expired_token_is_invalid_without_a_reuse_event() {
    // Acceptance criterion 3 (idle TTL): a token unused past its idle expiry does not
    // refresh, and it is a plain invalid_grant.
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x21_00_05);
    let scope = db.seed_scope(&env).await;
    let grant = seed_grant(&db, &env, scope, "usr_idle", None).await;
    let (_family, t0, _jti0, _d0) = open_family(
        &db,
        &env,
        scope,
        &grant,
        "usr_idle",
        false,
        5_000_000,
        FAR_FUTURE_MICROS,
    )
    .await;

    clock.advance(Duration::from_secs(10));
    let (outcome, _unused) = redeem(&db, &env, scope, &t0, true, Duration::from_secs(10)).await;
    assert_eq!(outcome, RefreshRedeemOutcome::Invalid);
    assert_eq!(count_action(&db, scope, "refresh_token.reuse").await, 0);
}

#[tokio::test]
async fn rp_logout_revokes_session_bound_families_but_offline_access_survives() {
    // Acceptance criterion 4: an offline_access family survives RP logout while a
    // session-bound family sharing the session is invalidated with it.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x21_00_06);
    let scope = db.seed_scope(&env).await;
    let session = create_session(&db, &env, scope, "usr_logout").await;

    // Two families under the SAME session: one session-bound, one offline_access.
    let bound_grant = seed_grant(&db, &env, scope, "usr_logout", Some(&session)).await;
    let (_bf, bound_token, _bj, _bd) = open_family(
        &db,
        &env,
        scope,
        &bound_grant,
        "usr_logout",
        false,
        FAR_FUTURE_MICROS,
        FAR_FUTURE_MICROS,
    )
    .await;
    let offline_grant = seed_grant(&db, &env, scope, "usr_logout", Some(&session)).await;
    let (_of, offline_token, _oj, _od) = open_family(
        &db,
        &env,
        scope,
        &offline_grant,
        "usr_logout",
        true,
        FAR_FUTURE_MICROS,
        FAR_FUTURE_MICROS,
    )
    .await;

    let revoked = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .refresh()
        .revoke_session_bound(&env, &session)
        .await
        .expect("revoke session-bound families");
    assert_eq!(
        revoked, 1,
        "exactly the one session-bound family is revoked"
    );

    assert!(
        !db.store()
            .scoped(scope)
            .refresh()
            .load(&bound_token)
            .await
            .expect("load")
            .expect("recorded")
            .active,
        "the session-bound family is invalidated with the session"
    );
    assert!(
        db.store()
            .scoped(scope)
            .refresh()
            .load(&offline_token)
            .await
            .expect("load")
            .expect("recorded")
            .active,
        "the offline_access family survives RP logout"
    );
    assert_eq!(
        count_action(&db, scope, "refresh_family.revoke").await,
        1,
        "one refresh_family.revoke audit row"
    );
    assert_eq!(
        count_action(&db, scope, "refresh_token.reuse").await,
        0,
        "an RP logout is not a reuse"
    );
}

/// Count the refresh families in scope bound to `session`, through the OWNER pool
/// (bypassing RLS), so a test can prove a refused open created NONE.
async fn families_bound_to(db: &TestDatabase, session: &SessionId) -> i64 {
    sqlx::query("SELECT count(*) AS c FROM refresh_families WHERE session_ref = $1")
        .bind(session.to_string())
        .fetch_one(db.owner_pool())
        .await
        .expect("count families")
        .get("c")
}

/// Open a family rooted at `grant` for `session_subject` with the given `offline`
/// flag, returning the open OUTCOME and the plaintext generation-0 token, WITHOUT
/// asserting success (the point of these tests is the outcome itself).
async fn issue_family(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    grant: &GrantId,
    subject: &str,
    offline: bool,
) -> (RefreshFamilyOpenOutcome, String, RefreshFamilyId) {
    let family_id = RefreshFamilyId::generate(env, &scope);
    let (token, jti, digest) = make_refresh_token(env, scope);
    let outcome = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .refresh()
        .issue(
            env,
            NewRefreshFamily {
                family_id: &family_id,
                token_jti: &jti,
                token_digest: &digest,
                grant_id: grant,
                subject,
                client_id: "cli_family",
                scope: Some("openid"),
                auth_methods: "pwd",
                offline,
                created_at_unix_micros: 0,
                idle_expires_at_unix_micros: FAR_FUTURE_MICROS,
                absolute_expires_at_unix_micros: FAR_FUTURE_MICROS,
            },
        )
        .await
        .expect("the issue call itself succeeds");
    (outcome, token, family_id)
}

#[tokio::test]
async fn a_session_bound_family_is_refused_when_its_session_died_in_the_open_window() {
    // Issue #32, the same class as the rotation-orphaning fix: the token endpoint's
    // liveness read and this family open run in SEPARATE transactions. A session revoke
    // that commits in the window between them (its cascade already run) must NOT leave a
    // fresh session-bound family bound to the now-dead session, outliving the logout
    // that should have killed it. The guarded open fails CLOSED with SessionNotLive and
    // writes nothing. Modeled by revoking the session directly between seeding the grant
    // and opening the family.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x32_00_01);
    let scope = db.seed_scope(&env).await;
    let session = create_session(&db, &env, scope, "usr_window").await;
    let grant = seed_grant(&db, &env, scope, "usr_window", Some(&session)).await;

    // The window revoke: the SSO session is logged out after the liveness read but
    // before the open.
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .sessions()
        .revoke(&env, &session, SessionEndCause::LoggedOut, false, None)
        .await
        .expect("revoke session in the window");

    let (outcome, token, _family) =
        issue_family(&db, &env, scope, &grant, "usr_window", false).await;
    assert_eq!(
        outcome,
        RefreshFamilyOpenOutcome::SessionNotLive,
        "a session-bound family whose session died in the window must be refused"
    );
    assert_eq!(
        families_bound_to(&db, &session).await,
        0,
        "NO session-bound refresh family exists after the refusal"
    );
    assert!(
        db.store()
            .scoped(scope)
            .refresh()
            .load(&token)
            .await
            .expect("load")
            .is_none(),
        "and no generation-0 refresh token was recorded"
    );
    assert_eq!(
        count_action(&db, scope, "refresh_token.issue").await,
        0,
        "a refused open writes no refresh_token.issue audit row"
    );
}

#[tokio::test]
async fn a_live_session_still_opens_its_session_bound_family() {
    // The other side of the guard: a genuinely LIVE session opens its family normally.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x32_00_02);
    let scope = db.seed_scope(&env).await;
    let session = create_session(&db, &env, scope, "usr_live").await;
    let grant = seed_grant(&db, &env, scope, "usr_live", Some(&session)).await;

    let (outcome, token, _family) = issue_family(&db, &env, scope, &grant, "usr_live", false).await;
    assert_eq!(
        outcome,
        RefreshFamilyOpenOutcome::Opened,
        "a live session opens its session-bound family"
    );
    assert_eq!(
        families_bound_to(&db, &session).await,
        1,
        "exactly one session-bound family exists"
    );
    assert!(
        db.store()
            .scoped(scope)
            .refresh()
            .load(&token)
            .await
            .expect("load")
            .expect("recorded")
            .active,
        "and its generation-0 token is live"
    );
}

#[tokio::test]
async fn an_offline_family_opens_even_when_its_session_is_already_dead() {
    // offline_access deliberately survives RP logout (issue #21), so the liveness guard
    // must NOT apply to it: the family opens even though the bound session is revoked.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x32_00_03);
    let scope = db.seed_scope(&env).await;
    let session = create_session(&db, &env, scope, "usr_offline").await;
    let grant = seed_grant(&db, &env, scope, "usr_offline", Some(&session)).await;
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .sessions()
        .revoke(&env, &session, SessionEndCause::LoggedOut, false, None)
        .await
        .expect("revoke session");

    let (outcome, token, _family) =
        issue_family(&db, &env, scope, &grant, "usr_offline", true).await;
    assert_eq!(
        outcome,
        RefreshFamilyOpenOutcome::Opened,
        "an offline_access family opens regardless of session liveness"
    );
    assert!(
        db.store()
            .scoped(scope)
            .refresh()
            .load(&token)
            .await
            .expect("load")
            .expect("recorded")
            .active,
        "and it is live: offline_access survives logout"
    );
}

#[tokio::test]
async fn a_grant_with_no_session_opens_its_family_unconditionally() {
    // A grant that never carried a session (session_ref NULL) is not session-bound, so
    // the guard does not apply and a non-offline family opens unconditionally.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x32_00_04);
    let scope = db.seed_scope(&env).await;
    let grant = seed_grant(&db, &env, scope, "usr_nosession", None).await;

    let (outcome, token, _family) =
        issue_family(&db, &env, scope, &grant, "usr_nosession", false).await;
    assert_eq!(
        outcome,
        RefreshFamilyOpenOutcome::Opened,
        "a grant with no session opens its family unconditionally"
    );
    assert!(
        db.store()
            .scoped(scope)
            .refresh()
            .load(&token)
            .await
            .expect("load")
            .expect("recorded")
            .active,
        "and its token is live"
    );
}

#[tokio::test]
async fn only_the_digest_is_stored_never_the_plaintext_refresh_token() {
    // Acceptance criterion 7 (data level, complementing the schema-level migration
    // test): a simulated database dump of refresh_tokens holds the one-way digest and
    // never the plaintext token.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x21_00_07);
    let scope = db.seed_scope(&env).await;
    let grant = seed_grant(&db, &env, scope, "usr_hash", None).await;
    let (_family, token, jti, digest) = open_family(
        &db,
        &env,
        scope,
        &grant,
        "usr_hash",
        false,
        FAR_FUTURE_MICROS,
        FAR_FUTURE_MICROS,
    )
    .await;

    // Dump every stored string column as the superuser (bypassing row-level security
    // exactly as a backup would).
    let rows = sqlx::query(
        "SELECT token_digest, family_id, jti, predecessor_jti, successor_jti \
         FROM refresh_tokens",
    )
    .fetch_all(db.owner_pool())
    .await
    .expect("dump refresh_tokens");
    assert_eq!(rows.len(), 1, "exactly one refresh token stored");
    let row = &rows[0];
    let stored_digest: String = row.get("token_digest");
    assert_eq!(
        stored_digest, digest,
        "the stored digest is SHA-256 of the whole token"
    );
    assert_eq!(row.get::<String, _>("jti"), jti.to_string());

    for col in ["token_digest", "family_id", "jti"] {
        let value: String = row.get(col);
        assert_ne!(
            value, token,
            "no stored column ({col}) holds the plaintext refresh token"
        );
    }
    // The optional predecessor/successor columns are NULL for a generation-0 token
    // and, whatever they hold, never the plaintext.
    for col in ["predecessor_jti", "successor_jti"] {
        let value: Option<String> = row.get(col);
        assert_ne!(value.as_deref(), Some(token.as_str()));
    }
}

/// PART 2 of issue #32 (defence in depth): a SESSION-BOUND refresh token must NEVER
/// mint after its bound session dies, even if a family were somehow left orphaned by a
/// missed revoke cascade. PART 1 makes that orphan unreachable through the open path;
/// this test manufactures it directly to prove redeem refuses it independently.
///
/// The manufactured state is exactly what a missed concurrent cascade leaves: the
/// SESSION is killed (as `revoke_session_in_tx`'s `UPDATE sessions` does) WITHOUT
/// touching the family, so the family stays live (`revoked_at IS NULL`) bound to a dead
/// session. Redeeming its token must be `invalid_grant`, not a fresh rotation.
#[tokio::test]
async fn redeem_refuses_a_session_bound_token_once_its_session_dies_even_off_an_orphan() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = "usr_orphan";
    let session = create_session(&db, &env, scope, subject).await;
    let grant = seed_grant(&db, &env, scope, subject, Some(&session)).await;
    let (_family, t0, _jti, _digest) = open_family(
        &db,
        &env,
        scope,
        &grant,
        subject,
        false,
        FAR_FUTURE_MICROS,
        FAR_FUTURE_MICROS,
    )
    .await;

    // Kill ONLY the session, deliberately skipping the family cascade, to forge the
    // orphan a missed concurrent cascade would leave.
    sqlx::query(
        "UPDATE sessions SET revoked_at = now(), ended_at = now(), \
         end_cause = 'revoked', revoke_reason = 'revoked' \
         WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
    )
    .bind(session.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .execute(db.owner_pool())
    .await
    .expect("kill only the session, not its family");

    // The orphan really exists: the family is still live while its session is dead.
    let family_live: bool = sqlx::query(
        "SELECT revoked_at IS NULL AS c FROM refresh_families \
         WHERE session_ref = $1 AND tenant_id = $2 AND environment_id = $3",
    )
    .bind(session.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("read family state")
    .get("c");
    assert!(
        family_live,
        "the manufactured orphan family must be live (cascade deliberately skipped)"
    );

    let (outcome, _succ) = redeem(&db, &env, scope, &t0, true, Duration::from_secs(10)).await;
    assert_eq!(
        outcome,
        RefreshRedeemOutcome::Invalid,
        "PART 2: a session-bound token never mints after its session dies, \
         even off a missed-cascade orphan"
    );
}

/// PART 2 must NOT break `offline_access`: an offline family deliberately SURVIVES its
/// session's logout (issue #21). The redeem-time session re-check is gated on
/// `offline = false`, so an offline token still rotates after its session dies.
#[tokio::test]
async fn redeem_still_rotates_an_offline_family_after_its_session_dies() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = "usr_offline";
    let session = create_session(&db, &env, scope, subject).await;
    let grant = seed_grant(&db, &env, scope, subject, Some(&session)).await;
    let (_family, t0, _jti, _digest) = open_family(
        &db,
        &env,
        scope,
        &grant,
        subject,
        true,
        FAR_FUTURE_MICROS,
        FAR_FUTURE_MICROS,
    )
    .await;

    // Kill the session (an ordinary logout). The offline family is intentionally left
    // untouched, as the #21 cascade leaves it.
    sqlx::query(
        "UPDATE sessions SET revoked_at = now(), ended_at = now(), \
         end_cause = 'revoked', revoke_reason = 'revoked' \
         WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
    )
    .bind(session.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .execute(db.owner_pool())
    .await
    .expect("log the session out");

    let (outcome, _succ) = redeem(&db, &env, scope, &t0, true, Duration::from_secs(10)).await;
    assert_eq!(
        outcome,
        RefreshRedeemOutcome::Rotated,
        "an offline_access token survives its session's logout and still rotates (issue #21)"
    );
}
