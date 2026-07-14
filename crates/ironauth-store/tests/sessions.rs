// SPDX-License-Identifier: MIT OR Apache-2.0

//! The authoritative two-tier session model (issue #32), against a real database.
//!
//! These pin the hazards the milestone is defined by:
//!
//! - IMMEDIATE revocation: a revoked or rotated session stops resolving AT ONCE, not
//!   when its lifetime happens to elapse. An expiry-only guard would let every logout
//!   silently no-op, so the tests assert the read path refuses a revoked session while
//!   its expiry is still far in the future.
//! - The `sid` tier: STABLE per (client, session) across refreshes, DISTINCT across
//!   two clients of the same SSO session (never `sid = session_id`, which would leak
//!   cross-client correlation to colluding relying parties).
//! - Session-fixation defense: a login rotates the id and INVALIDATES the prior one in
//!   the same transaction.
//! - The revoke cascade: it reaches the session-bound refresh families and PRESERVES
//!   the `offline_access` families (issue #21's offline-survives-logout semantic)
//!   unless an explicit hard kill is asked for.
//! - Same-transaction audit: a forced failure after both inserts leaves neither.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    AuthorizationCodeId, ClientId, CorrelationId, GrantId, IssueCode, NewRefreshFamily, NewSession,
    RefreshFamilyId, RefreshTokenId, Scope, SessionEndCause, SessionFleetFilter, SessionId,
    StoreError, UserId, refresh_token_digest,
};
use sqlx::Row;

/// A far-future expiry (year 2100) in epoch microseconds. Every session in this file
/// is created with a lifetime this long, so a session that stops resolving can ONLY
/// have stopped because of revocation or rotation, never because it expired. That is
/// what makes "immediate, not expiry-gated" a real assertion rather than a coincidence.
const FAR_FUTURE_MICROS: i64 = 4_102_444_800_000_000;

/// Create a session in `scope` for `subject`, rotating away `prior` if given.
async fn create_session(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    subject: &str,
    prior: Option<&SessionId>,
) -> SessionId {
    let id = SessionId::generate(env, &scope);
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .sessions()
        .rotate(
            env,
            &id,
            prior,
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
        .expect("rotate session");
    id
}

/// Issue a grant carrying `session_ref`, so a family rooted at it is session bound.
async fn seed_grant(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    subject: &str,
    session: &SessionId,
) -> GrantId {
    let code_id = AuthorizationCodeId::generate(env, &scope);
    let grant_id = GrantId::generate(env, &scope);
    let client_id = ClientId::generate(env, &scope);
    let session_text = session.to_string();
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
                session_ref: Some(&session_text),
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

/// Open a refresh family rooted at `grant_id` (session bound or `offline_access`).
async fn open_family(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    grant_id: &GrantId,
    subject: &str,
    offline: bool,
) -> RefreshFamilyId {
    let family_id = RefreshFamilyId::generate(env, &scope);
    let jti = RefreshTokenId::generate(env, &scope);
    let digest = refresh_token_digest(&format!("ira_rt_{jti}~seed"));
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
                idle_expires_at_unix_micros: FAR_FUTURE_MICROS,
                absolute_expires_at_unix_micros: FAR_FUTURE_MICROS,
            },
        )
        .await
        .expect("open family");
    family_id
}

/// Whether a refresh family is revoked, read through the fleet surface.
async fn family_revoked(db: &TestDatabase, scope: Scope, family: &RefreshFamilyId) -> bool {
    db.store()
        .scoped(scope)
        .refresh_family_fleet()
        .get(family)
        .await
        .expect("read family")
        .expect("family exists")
        .revoked_at_unix_micros
        .is_some()
}

/// Count the audit rows carrying `action`, through the owner pool (bypasses RLS).
async fn audit_count(db: &TestDatabase, action: &str) -> i64 {
    sqlx::query("SELECT count(*) AS c FROM audit_log WHERE action = $1")
        .bind(action)
        .fetch_one(db.owner_pool())
        .await
        .expect("count audit rows")
        .get("c")
}

#[tokio::test]
async fn a_revoked_session_stops_resolving_immediately_not_on_expiry() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = UserId::generate(&env, &scope).to_string();
    let session = create_session(&db, &env, scope, &subject, None).await;

    // Baseline: the session resolves NOW (its lifetime runs to the year 2100).
    let sessions = db.store().scoped(scope).sessions();
    assert!(
        sessions.get(&session, 0).await.expect("read").is_some(),
        "a live session resolves"
    );

    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .sessions()
        .revoke(&env, &session, SessionEndCause::LoggedOut, false, None)
        .await
        .expect("revoke");

    // The milestone-defining invariant: the very next read refuses it, with its
    // expiry still 75 years away. An expiry-only guard would have returned it here
    // and the logout would have silently no-opped.
    assert!(
        sessions.get(&session, 0).await.expect("read").is_none(),
        "a revoked session must stop resolving IMMEDIATELY, not at expiry"
    );

    // A second revoke is a no-op (idempotent), and the session stays gone.
    let again = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .sessions()
        .revoke(&env, &session, SessionEndCause::LoggedOut, false, None)
        .await
        .expect("re-revoke");
    assert!(
        !again.session_flipped,
        "an already-revoked session does not flip twice"
    );
    assert!(sessions.get(&session, 0).await.expect("read").is_none());
}

#[tokio::test]
async fn login_rotation_invalidates_the_prior_session_id_in_the_same_transaction() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = UserId::generate(&env, &scope).to_string();

    // The session the browser holds before the privilege transition.
    let prior = create_session(&db, &env, scope, &subject, None).await;
    let sessions = db.store().scoped(scope).sessions();
    assert!(sessions.get(&prior, 0).await.expect("read").is_some());

    // The login: a fresh id, and the prior one invalidated in the SAME transaction.
    let fresh = create_session(&db, &env, scope, &subject, Some(&prior)).await;
    assert_ne!(fresh, prior, "rotation mints a fresh entropy-seam id");

    // Session-fixation defense: the id an attacker may have fixated stops resolving.
    assert!(
        sessions.get(&prior, 0).await.expect("read").is_none(),
        "the prior session id must stop resolving after a rotation"
    );
    assert!(
        sessions.get(&fresh, 0).await.expect("read").is_some(),
        "the successor resolves"
    );

    // The fleet surface records the lineage, so a rotation is inspectable and is NOT
    // reported as a terminal revoke: end_cause is `rotated` and a successor is named.
    let rotated = db
        .store()
        .scoped(scope)
        .session_fleet()
        .get(&prior)
        .await
        .expect("read")
        .expect("prior still inspectable");
    assert_eq!(rotated.end_cause.as_deref(), Some("rotated"));
    assert_eq!(
        rotated.superseded_by.as_deref(),
        Some(fresh.to_string()).as_deref()
    );
    assert!(
        rotated.revoked_at_unix_micros.is_none(),
        "a rotation is not a revocation"
    );

    // The audit trail names a rotation distinctly from a create.
    assert!(audit_count(&db, "session.rotate").await >= 1);
}

#[tokio::test]
async fn sid_is_stable_per_client_session_pair_and_distinct_across_clients() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = UserId::generate(&env, &scope).to_string();
    let session = create_session(&db, &env, scope, &subject, None).await;
    let client_sessions = db.store().scoped(scope).client_sessions();

    // Client A's first ID token.
    let a1 = client_sessions
        .ensure_sid(&env, &session, "cli_a", 0)
        .await
        .expect("sid for A");
    // A token refresh / re-authorization for the SAME (client, session) pair.
    let a2 = client_sessions
        .ensure_sid(&env, &session, "cli_a", 10)
        .await
        .expect("sid for A again");
    assert_eq!(a1, a2, "sid is STABLE for one (client, session) pair");

    // A DIFFERENT client of the SAME SSO session.
    let b1 = client_sessions
        .ensure_sid(&env, &session, "cli_b", 20)
        .await
        .expect("sid for B");
    assert_ne!(
        a1, b1,
        "two clients of one SSO session must get DISTINCT sids (colluding relying \
         parties must not be able to correlate the user across clients)"
    );

    // And never `sid = session_id`, which would be exactly that correlation leak.
    let session_text = session.to_string();
    assert_ne!(a1, session_text);
    assert_ne!(b1, session_text);

    // A second SSO session for the same subject and the same client gets its own sid.
    let other = create_session(&db, &env, scope, &subject, None).await;
    let a_other = client_sessions
        .ensure_sid(&env, &other, "cli_a", 30)
        .await
        .expect("sid for A on the other session");
    assert_ne!(a1, a_other, "sid is per (client, SESSION), not per client");
}

#[tokio::test]
async fn revoking_a_session_cascades_to_families_but_preserves_offline_access() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = UserId::generate(&env, &scope).to_string();
    let session = create_session(&db, &env, scope, &subject, None).await;

    let bound_grant = seed_grant(&db, &env, scope, &subject, &session).await;
    let bound = open_family(&db, &env, scope, &bound_grant, &subject, false).await;
    let offline_grant = seed_grant(&db, &env, scope, &subject, &session).await;
    let offline = open_family(&db, &env, scope, &offline_grant, &subject, true).await;

    let outcome = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .sessions()
        .revoke(&env, &session, SessionEndCause::Revoked, false, None)
        .await
        .expect("revoke");
    assert!(outcome.session_flipped);
    assert_eq!(outcome.families_revoked, 1, "only the session-bound family");

    assert!(
        family_revoked(&db, scope, &bound).await,
        "the session-bound family is revoked with its session"
    );
    assert!(
        !family_revoked(&db, scope, &offline).await,
        "an offline_access family SURVIVES a session revocation (issue #21)"
    );
}

#[tokio::test]
async fn the_hard_kill_flag_also_ends_the_offline_access_families() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = UserId::generate(&env, &scope).to_string();
    let session = create_session(&db, &env, scope, &subject, None).await;

    let offline_grant = seed_grant(&db, &env, scope, &subject, &session).await;
    let offline = open_family(&db, &env, scope, &offline_grant, &subject, true).await;

    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .sessions()
        .revoke(&env, &session, SessionEndCause::Revoked, true, None)
        .await
        .expect("hard-kill revoke");

    assert!(
        family_revoked(&db, scope, &offline).await,
        "an explicit hard kill ends the offline_access families too"
    );
    // The hard kill also revokes the grant behind the family, so the access tokens
    // derived from it (whose active state comes from grants.revoked_at) die at once.
    let grant_revoked: bool =
        sqlx::query("SELECT revoked_at IS NOT NULL AS r FROM grants WHERE id = $1")
            .bind(offline_grant.to_string())
            .fetch_one(db.owner_pool())
            .await
            .expect("read grant")
            .get("r");
    assert!(grant_revoked, "a hard kill revokes the grant too");
}

#[tokio::test]
async fn revoke_all_for_a_user_ends_every_session_and_cascades_offline_preservingly() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let victim = UserId::generate(&env, &scope);
    let subject = victim.to_string();
    let bystander = UserId::generate(&env, &scope).to_string();

    let s1 = create_session(&db, &env, scope, &subject, None).await;
    let s2 = create_session(&db, &env, scope, &subject, None).await;
    let other = create_session(&db, &env, scope, &bystander, None).await;

    let bound_grant = seed_grant(&db, &env, scope, &subject, &s1).await;
    let bound = open_family(&db, &env, scope, &bound_grant, &subject, false).await;
    let offline_grant = seed_grant(&db, &env, scope, &subject, &s2).await;
    let offline = open_family(&db, &env, scope, &offline_grant, &subject, true).await;

    let outcome = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .sessions()
        .revoke_all_for_user(&env, &victim, false, None)
        .await
        .expect("revoke all");
    assert_eq!(outcome.sessions_revoked, 2, "both of the user's sessions");
    assert_eq!(outcome.families_revoked, 1, "only the session-bound family");

    let sessions = db.store().scoped(scope).sessions();
    assert!(sessions.get(&s1, 0).await.expect("read").is_none());
    assert!(sessions.get(&s2, 0).await.expect("read").is_none());
    assert!(
        sessions.get(&other, 0).await.expect("read").is_some(),
        "another user's session is untouched"
    );
    assert!(family_revoked(&db, scope, &bound).await);
    assert!(
        !family_revoked(&db, scope, &offline).await,
        "offline_access survives a revoke-everything unless a hard kill is asked for"
    );
}

#[tokio::test]
async fn a_bulk_revoke_is_scope_fenced_and_audits_every_session() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let subject_a = UserId::generate(&env, &scope_a).to_string();
    let subject_b = UserId::generate(&env, &scope_b).to_string();

    let mine_1 = create_session(&db, &env, scope_a, &subject_a, None).await;
    let mine_2 = create_session(&db, &env, scope_a, &subject_a, None).await;
    let foreign = create_session(&db, &env, scope_b, &subject_b, None).await;

    let before = audit_count(&db, "sessions.bulk_revoke").await;
    let flipped = db
        .store()
        .scoped(scope_a)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .sessions()
        // The foreign session is smuggled into an otherwise valid batch.
        .bulk_revoke(&env, &[mine_1, mine_2, foreign], false, None)
        .await
        .expect("bulk revoke");
    assert_eq!(flipped, 2, "only the caller's OWN sessions are revoked");

    // The scope fence held: the other tenant's session still resolves.
    assert!(
        db.store()
            .scoped(scope_b)
            .sessions()
            .get(&foreign, 0)
            .await
            .expect("read")
            .is_some(),
        "a bulk revoke must never reach another tenant's session"
    );
    // One audit row PER in-scope session, so the trail names each one (the foreign id
    // never reaches a query, so it is never audited either).
    assert_eq!(audit_count(&db, "sessions.bulk_revoke").await - before, 2);
}

#[tokio::test]
async fn the_fleet_surface_searches_by_user_and_by_client() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let alice = UserId::generate(&env, &scope).to_string();
    let bob = UserId::generate(&env, &scope).to_string();

    let alice_session = create_session(&db, &env, scope, &alice, None).await;
    let bob_session = create_session(&db, &env, scope, &bob, None).await;
    // Alice's session has a per-client session for cli_a; Bob's does not.
    db.store()
        .scoped(scope)
        .client_sessions()
        .ensure_sid(&env, &alice_session, "cli_a", 0)
        .await
        .expect("sid");

    let fleet = db.store().scoped(scope).session_fleet();
    let all = fleet
        .list(SessionFleetFilter::default(), 50, None)
        .await
        .expect("list all");
    assert_eq!(all.len(), 2, "an empty filter lists every session in scope");

    let by_user = fleet
        .list(
            SessionFleetFilter {
                subject: Some(&alice),
                client_id: None,
            },
            50,
            None,
        )
        .await
        .expect("list by user");
    assert_eq!(by_user.len(), 1);
    assert_eq!(by_user[0].id, alice_session.to_string());

    let by_client = fleet
        .list(
            SessionFleetFilter {
                subject: None,
                client_id: Some("cli_a"),
            },
            50,
            None,
        )
        .await
        .expect("list by client");
    assert_eq!(by_client.len(), 1, "only the session that has that client");
    assert_eq!(by_client[0].id, alice_session.to_string());
    assert_ne!(by_client[0].id, bob_session.to_string());
}

#[tokio::test]
async fn a_revocation_and_its_audit_row_commit_together_or_not_at_all() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = UserId::generate(&env, &scope).to_string();
    let session = create_session(&db, &env, scope, &subject, None).await;

    let audits_before = audit_count(&db, "session.revoke").await;

    // Run a REAL revoke (the session flip, the cascade, and the audit insert), then
    // force a guaranteed failure inside the SAME transaction.
    let result = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .sessions()
        .revoke_injecting_post_audit_failure(&env, &session, SessionEndCause::Revoked)
        .await;
    assert!(
        matches!(result, Err(StoreError::Database(_))),
        "the poisoned revoke must fail: {result:?}"
    );

    // Neither half survived: the session still resolves AND no audit row was written.
    // A revocation without its audit row (or an audit row without its revocation) is
    // not representable.
    assert!(
        db.store()
            .scoped(scope)
            .sessions()
            .get(&session, 0)
            .await
            .expect("read")
            .is_some(),
        "a rolled-back revocation leaves the session live"
    );
    assert_eq!(
        audit_count(&db, "session.revoke").await,
        audits_before,
        "a rolled-back revocation leaves no orphan audit row"
    );
}

#[tokio::test]
async fn a_rotation_and_its_audit_row_commit_together_or_not_at_all() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = UserId::generate(&env, &scope).to_string();
    let prior = create_session(&db, &env, scope, &subject, None).await;
    let fresh = SessionId::generate(&env, &scope);

    let audits_before = audit_count(&db, "session.rotate").await;
    let result = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .sessions()
        .rotate_injecting_post_audit_failure(
            &env,
            &fresh,
            Some(&prior),
            NewSession {
                subject: &subject,
                auth_methods: "pwd",
                auth_time_micros: 0,
                idle_expires_micros: FAR_FUTURE_MICROS,
                absolute_expires_micros: FAR_FUTURE_MICROS,
                user_agent: None,
                peer_ip: None,
            },
        )
        .await;
    assert!(
        matches!(result, Err(StoreError::Database(_))),
        "the poisoned rotation must fail: {result:?}"
    );

    let sessions = db.store().scoped(scope).sessions();
    assert!(
        sessions.get(&prior, 0).await.expect("read").is_some(),
        "a rolled-back rotation leaves the PRIOR session live (it was not invalidated)"
    );
    assert!(
        sessions.get(&fresh, 0).await.expect("read").is_none(),
        "a rolled-back rotation creates no successor"
    );
    assert_eq!(
        audit_count(&db, "session.rotate").await,
        audits_before,
        "a rolled-back rotation leaves no orphan audit row"
    );
}

#[tokio::test]
async fn every_fleet_surface_returns_the_uniform_not_found_for_a_foreign_id() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let subject_b = UserId::generate(&env, &scope_b).to_string();
    let victim = create_session(&db, &env, scope_b, &subject_b, None).await;

    // Reading a foreign session by id through the fleet surface: the id does not even
    // parse under the caller's scope, which is the uniform not-found (the anti-oracle:
    // exactly what an absent id in the caller's own scope produces).
    let fleet_a = db.store().scoped(scope_a).session_fleet();
    assert!(matches!(
        fleet_a.parse_id(&victim.to_string()),
        Err(StoreError::NotFound)
    ));
    let absent_in_a = SessionId::generate(&env, &scope_a);
    assert!(
        fleet_a.get(&absent_in_a).await.expect("read").is_none(),
        "an absent id in the caller's own scope is None, the same shape"
    );

    // Listing in scope A never reports scope B's session.
    let listed = fleet_a
        .list(SessionFleetFilter::default(), 50, None)
        .await
        .expect("list");
    assert!(listed.is_empty(), "a foreign session is never listed");

    // Revoking a foreign session is the uniform not-found, and the victim survives.
    let revoke = db
        .store()
        .scoped(scope_a)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .sessions()
        .revoke(&env, &victim, SessionEndCause::Revoked, false, None)
        .await;
    assert!(matches!(revoke, Err(StoreError::NotFound)));
    assert!(
        db.store()
            .scoped(scope_b)
            .sessions()
            .get(&victim, 0)
            .await
            .expect("read")
            .is_some(),
        "the foreign session is untouched"
    );

    // Revoking everything for a foreign USER is likewise the uniform not-found.
    let foreign_user = UserId::generate(&env, &scope_b);
    let revoke_all = db
        .store()
        .scoped(scope_a)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .sessions()
        .revoke_all_for_user(&env, &foreign_user, false, None)
        .await;
    assert!(matches!(revoke_all, Err(StoreError::NotFound)));

    // And a per-client sid can never be minted against a foreign SSO session.
    let sid = db
        .store()
        .scoped(scope_a)
        .client_sessions()
        .ensure_sid(&env, &victim, "cli_a", 0)
        .await;
    assert!(matches!(sid, Err(StoreError::NotFound)));
}
