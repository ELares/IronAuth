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
    RefreshFamilyId, RefreshFamilyOpenOutcome, RefreshTokenId, Scope, SessionEndCause,
    SessionFleetFilter, SessionId, StoreError, UserId, refresh_token_digest,
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
                browserless: false,
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
                auth_time_unix_micros: None,
                offline,
                created_at_unix_micros: 0,
                idle_expires_at_unix_micros: FAR_FUTURE_MICROS,
                absolute_expires_at_unix_micros: FAR_FUTURE_MICROS,
                dpop_jkt: None,
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
        sessions.get(&session, 0, 0).await.expect("read").is_some(),
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
        sessions.get(&session, 0, 0).await.expect("read").is_none(),
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
    assert!(sessions.get(&session, 0, 0).await.expect("read").is_none());
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
    assert!(sessions.get(&prior, 0, 0).await.expect("read").is_some());

    // The login: a fresh id, and the prior one invalidated in the SAME transaction.
    let fresh = create_session(&db, &env, scope, &subject, Some(&prior)).await;
    assert_ne!(fresh, prior, "rotation mints a fresh entropy-seam id");

    // Session-fixation defense: the id an attacker may have fixated stops resolving.
    assert!(
        sessions.get(&prior, 0, 0).await.expect("read").is_none(),
        "the prior session id must stop resolving after a rotation"
    );
    assert!(
        sessions.get(&fresh, 0, 0).await.expect("read").is_some(),
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
async fn session_for_sid_maps_a_client_sid_back_to_its_sso_session() {
    // RP-Initiated Logout (issue #33) targets the SSO session by the per-client `sid`
    // its id_token_hint carries. The reverse lookup maps that sid back to the tier-one
    // session, is scope-fenced, and returns None for an unknown sid.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = UserId::generate(&env, &scope).to_string();
    let session = create_session(&db, &env, scope, &subject, None).await;
    let client_sessions = db.store().scoped(scope).client_sessions();

    let sid = client_sessions
        .ensure_sid(&env, &session, "cli_a", 0)
        .await
        .expect("sid for A");

    // The sid maps back to exactly the SSO session it was minted for.
    let resolved = client_sessions
        .session_for_sid(&sid)
        .await
        .expect("lookup ok");
    assert_eq!(
        resolved,
        Some(session),
        "the sid resolves to its SSO session"
    );

    // A distinct client's sid on the same session resolves to the same session.
    let sid_b = client_sessions
        .ensure_sid(&env, &session, "cli_b", 0)
        .await
        .expect("sid for B");
    assert_ne!(sid, sid_b, "distinct clients get distinct sids");
    assert_eq!(
        client_sessions
            .session_for_sid(&sid_b)
            .await
            .expect("lookup"),
        Some(session)
    );

    // An unknown sid is a clean miss, never an error and never another tenant's session.
    assert_eq!(
        client_sessions
            .session_for_sid("sid_deadbeef")
            .await
            .expect("lookup ok"),
        None
    );

    // A second tenant's identical-shaped sid never resolves here: scope-fenced.
    let other_scope = db.seed_scope(&env).await;
    let other = db.store().scoped(other_scope).client_sessions();
    assert_eq!(
        other.session_for_sid(&sid).await.expect("lookup ok"),
        None,
        "a sid never resolves across a tenant boundary"
    );
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
    // The revoked-session ids are returned (issue #36 fan-out source): exactly the two
    // sessions that flipped, and nobody else's.
    let mut returned = outcome.revoked_session_ids.clone();
    returned.sort();
    let mut expected = vec![s1.to_string(), s2.to_string()];
    expected.sort();
    assert_eq!(
        returned, expected,
        "revoked_session_ids names exactly the flipped sessions"
    );

    let sessions = db.store().scoped(scope).sessions();
    assert!(sessions.get(&s1, 0, 0).await.expect("read").is_none());
    assert!(sessions.get(&s2, 0, 0).await.expect("read").is_none());
    assert!(
        sessions.get(&other, 0, 0).await.expect("read").is_some(),
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
            .get(&foreign, 0, 0)
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
            .get(&session, 0, 0)
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
        sessions.get(&prior, 0, 0).await.expect("read").is_some(),
        "a rolled-back rotation leaves the PRIOR session live (it was not invalidated)"
    );
    assert!(
        sessions.get(&fresh, 0, 0).await.expect("read").is_none(),
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
            .get(&victim, 0, 0)
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

/// The `sid` of a (session, client) pair as the store holds it, or [`None`].
async fn stored_sid(
    db: &TestDatabase,
    scope: Scope,
    session: &SessionId,
    client_id: &str,
) -> Option<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT sid FROM client_sessions \
         WHERE session_id = $1 AND client_id = $2 AND tenant_id = $3 AND environment_id = $4",
    )
    .bind(session.to_string())
    .bind(client_id)
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_optional(db.owner_pool())
    .await
    .expect("read sid")
}

/// How many refresh families point at `session`, whatever their revocation state.
async fn families_pointing_at(db: &TestDatabase, scope: Scope, session: &SessionId) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM refresh_families \
         WHERE session_ref = $1 AND tenant_id = $2 AND environment_id = $3",
    )
    .bind(session.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("count families")
}

/// How many per-client sessions hang off `session`, whatever their revocation state.
async fn client_sessions_on(db: &TestDatabase, scope: Scope, session: &SessionId) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM client_sessions \
         WHERE session_id = $1 AND tenant_id = $2 AND environment_id = $3",
    )
    .bind(session.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("count client sessions")
}

/// The session's `end_cause`, if it has ended.
async fn end_cause(db: &TestDatabase, scope: Scope, session: &SessionId) -> Option<String> {
    sqlx::query_scalar::<_, Option<String>>(
        "SELECT end_cause FROM sessions \
         WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
    )
    .bind(session.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("read end_cause")
}

#[tokio::test]
async fn a_same_subject_reauth_carries_the_lineage_so_a_later_revoke_still_reaches_it() {
    // The milestone-defining hazard. A login ROTATES the session id. If the rotation
    // moved only the `sessions` row, everything the PRE-rotation lineage segment opened
    // (its refresh families, its per-client sessions) would be ORPHANED: they would keep
    // session_ref = <prior>, and every later cascade runs on session_ref = <successor>,
    // so nothing would ever reach them. The user's refresh tokens from before the
    // re-authentication would stay valid FOREVER and logout would not actually revoke.
    //
    // So a same-subject rotation must CARRY the lineage forward. This test proves both
    // halves of that: the sid stays stable, and the pre-rotation family is still KILLED
    // when the successor is revoked.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = UserId::generate(&env, &scope).to_string();
    let client = "cli_carry";

    // A session, a per-client sid on it, and a session-bound refresh family.
    let prior = create_session(&db, &env, scope, &subject, None).await;
    let sid_before = db
        .store()
        .scoped(scope)
        .client_sessions()
        .ensure_sid(&env, &prior, client, 0)
        .await
        .expect("ensure sid");
    let grant = seed_grant(&db, &env, scope, &subject, &prior).await;
    let family = open_family(&db, &env, scope, &grant, &subject, false).await;

    // The SAME human re-authenticates in the SAME browser: a rotation.
    let successor = create_session(&db, &env, scope, &subject, Some(&prior)).await;

    // The lineage moved: nothing is left hanging off the prior id.
    assert_eq!(
        families_pointing_at(&db, scope, &prior).await,
        0,
        "the pre-rotation family must NOT be left orphaned on the prior session"
    );
    assert_eq!(
        families_pointing_at(&db, scope, &successor).await,
        1,
        "the pre-rotation family must be carried onto the successor"
    );
    assert_eq!(client_sessions_on(&db, scope, &prior).await, 0);
    assert_eq!(client_sessions_on(&db, scope, &successor).await, 1);

    // The sid is STABLE across the re-authentication: same browser SSO session, same
    // sid, which is exactly what the OIDC sid contract wants.
    let sid_after = db
        .store()
        .scoped(scope)
        .client_sessions()
        .ensure_sid(&env, &successor, client, 0)
        .await
        .expect("ensure sid after rotation");
    assert_eq!(
        sid_after, sid_before,
        "the sid must be STABLE across a re-authentication of the same user"
    );
    assert_eq!(
        stored_sid(&db, scope, &successor, client).await.as_deref(),
        Some(sid_before.as_str()),
    );

    // THE assertion: revoking the successor still reaches the family the PRE-rotation
    // lineage segment opened. With the carry reverted this fails: the family would keep
    // session_ref = <prior> and the cascade on <successor> would miss it entirely.
    let outcome = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .sessions()
        .revoke(&env, &successor, SessionEndCause::LoggedOut, false, None)
        .await
        .expect("revoke successor");
    assert_eq!(
        outcome.families_revoked, 1,
        "logout MUST cascade to the family opened before the rotation"
    );
    assert!(
        family_revoked(&db, scope, &family).await,
        "the pre-rotation refresh family must die with the session it belongs to"
    );
}

#[tokio::test]
async fn a_different_subject_login_terminally_revokes_the_prior_session_and_inherits_nothing() {
    // The cross-user privilege escalation the obvious fix would introduce. A rotation
    // happens at a privilege TRANSITION, and the prior session is not necessarily the
    // rotating user's: a login performed while presenting SOMEBODY ELSE's session cookie
    // lands on the same path. Carrying the lineage there would hand the incoming user
    // the OUTGOING user's refresh families and sids.
    //
    // So a different-subject rotation must CARRY NOTHING and terminally revoke the prior
    // session with its full cascade.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let victim = UserId::generate(&env, &scope).to_string();
    let attacker = UserId::generate(&env, &scope).to_string();
    let client = "cli_takeover";

    // The victim's session, with a sid and a session-bound refresh family on it.
    let victim_session = create_session(&db, &env, scope, &victim, None).await;
    let victim_sid = db
        .store()
        .scoped(scope)
        .client_sessions()
        .ensure_sid(&env, &victim_session, client, 0)
        .await
        .expect("victim sid");
    let victim_grant = seed_grant(&db, &env, scope, &victim, &victim_session).await;
    let victim_family = open_family(&db, &env, scope, &victim_grant, &victim, false).await;

    // A DIFFERENT human logs in while the victim's cookie is still being presented.
    let attacker_session = create_session(&db, &env, scope, &attacker, Some(&victim_session)).await;

    // Nothing was inherited. The attacker's session owns NONE of the victim's
    // dependents: no carried family, no carried per-client session (hence no carried
    // sid). Read straight from the database, not through a repository that could be
    // lying by the same bug.
    assert_eq!(
        families_pointing_at(&db, scope, &attacker_session).await,
        0,
        "the incoming user must NOT inherit the outgoing user's refresh families"
    );
    assert_eq!(
        client_sessions_on(&db, scope, &attacker_session).await,
        0,
        "the incoming user must NOT inherit the outgoing user's per-client sessions"
    );

    // The victim's dependents stayed the victim's, and were REVOKED at the transition.
    assert_eq!(families_pointing_at(&db, scope, &victim_session).await, 1);
    assert!(
        family_revoked(&db, scope, &victim_family).await,
        "the outgoing user's session-bound family must die at the transition"
    );
    assert_eq!(
        end_cause(&db, scope, &victim_session).await.as_deref(),
        Some("replaced_by_other_subject"),
        "the prior session ended TERMINALLY, not as a rotation"
    );

    // The victim's session no longer resolves, and the attacker cannot obtain the
    // victim's sid: a fresh (attacker session, client) pair mints a NEW one.
    let sessions = db.store().scoped(scope).sessions();
    assert!(
        sessions
            .get(&victim_session, 0, 0)
            .await
            .expect("read")
            .is_none(),
        "the terminally revoked session must stop resolving at once"
    );
    let attacker_sid = db
        .store()
        .scoped(scope)
        .client_sessions()
        .ensure_sid(&env, &attacker_session, client, 0)
        .await
        .expect("attacker sid");
    assert_ne!(
        attacker_sid, victim_sid,
        "the incoming user must never be handed the outgoing user's sid"
    );
}

#[tokio::test]
async fn ensure_sid_refuses_a_dead_session_so_no_sid_is_ever_minted_for_one() {
    // Defense in depth for the token endpoint (a code minted before a revoke and
    // redeemed after it): the store must never hang a LIVE per-client session, with a
    // fresh sid, off a session that is already dead. No cascade would ever reach it.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = UserId::generate(&env, &scope).to_string();
    let session = create_session(&db, &env, scope, &subject, None).await;

    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .sessions()
        .revoke(&env, &session, SessionEndCause::LoggedOut, false, None)
        .await
        .expect("revoke");

    let result = db
        .store()
        .scoped(scope)
        .client_sessions()
        .ensure_sid(&env, &session, "cli_dead", 0)
        .await;
    assert!(
        matches!(result, Err(StoreError::NotFound)),
        "a revoked session must never mint a sid, got {result:?}"
    );
    assert_eq!(
        client_sessions_on(&db, scope, &session).await,
        0,
        "no per-client session row may be created for a dead SSO session"
    );
}

#[tokio::test]
async fn an_active_session_slides_its_idle_window_while_an_idle_one_dies_at_the_idle_ttl() {
    // session_idle_ttl_secs is documented as an IDLE timeout. Nothing slid it, so it was
    // a second ABSOLUTE cap: a CONTINUOUSLY ACTIVE session was killed at idle_ttl. A
    // successful resolve is exactly the evidence the session is not idle, so it must
    // slide the window.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = UserId::generate(&env, &scope).to_string();

    // A ten-second idle window inside a far-future absolute cap, so anything that dies
    // here died of IDLENESS, never of the absolute cap.
    //
    // Three sessions, because a successful resolve IS activity and therefore slides:
    // the two idle probes must each be read EXACTLY ONCE, or the first read would touch
    // them and the second would be measuring the slide rather than the timeout.
    let idle_ttl: i64 = 10_000_000;
    let touched = SessionId::generate(&env, &scope);
    let idle_just_alive = SessionId::generate(&env, &scope);
    let idle_just_dead = SessionId::generate(&env, &scope);
    for id in [&touched, &idle_just_alive, &idle_just_dead] {
        db.store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .sessions()
            .rotate(
                &env,
                id,
                None,
                NewSession {
                    subject: &subject,
                    auth_methods: "pwd",
                    auth_time_micros: 0,
                    idle_expires_micros: idle_ttl,
                    absolute_expires_micros: FAR_FUTURE_MICROS,
                    user_agent: None,
                    peer_ip: None,
                },
            )
            .await
            .expect("create session");
    }

    let sessions = db.store().scoped(scope).sessions();

    // Touch the active session every 0.6 idle windows, well past the point where an
    // unslid window would have lapsed. It must survive indefinitely.
    let step = idle_ttl * 6 / 10;
    let mut now = 0_i64;
    for _ in 0..10 {
        now += step;
        assert!(
            sessions
                .get(&touched, now, idle_ttl)
                .await
                .expect("read")
                .is_some(),
            "a CONTINUOUSLY ACTIVE session must never hit the idle timeout (t={now})"
        );
    }
    // Six idle windows have now elapsed since it was created.
    assert!(now > idle_ttl * 5);

    // The UNTOUCHED sessions die exactly at their idle TTL: the timeout still bites, so
    // the slide made the window slide without disabling it. Each probe is resolved
    // exactly once (a resolve is a touch, and a touched session is by definition not
    // idle).
    assert!(
        sessions
            .get(&idle_just_alive, idle_ttl - 1, idle_ttl)
            .await
            .expect("read")
            .is_some(),
        "an idle session is alive right up to its idle expiry"
    );
    assert!(
        sessions
            .get(&idle_just_dead, idle_ttl, idle_ttl)
            .await
            .expect("read")
            .is_none(),
        "an idle session dies AT its idle expiry: the slide must not disable the timeout"
    );
}

#[tokio::test]
async fn a_slide_never_resurrects_a_revoked_session() {
    // The slide writes idle_expires_at. It must re-assert the FULL liveness guard, or a
    // resolve racing a revoke could push a dead session's window forward and hand it
    // back to life.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = UserId::generate(&env, &scope).to_string();
    let idle_ttl: i64 = 10_000_000;

    let session = SessionId::generate(&env, &scope);
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .sessions()
        .rotate(
            &env,
            &session,
            None,
            NewSession {
                subject: &subject,
                auth_methods: "pwd",
                auth_time_micros: 0,
                idle_expires_micros: idle_ttl,
                absolute_expires_micros: FAR_FUTURE_MICROS,
                user_agent: None,
                peer_ip: None,
            },
        )
        .await
        .expect("create session");

    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .sessions()
        .revoke(&env, &session, SessionEndCause::LoggedOut, false, None)
        .await
        .expect("revoke");

    // Resolve well inside the idle window: the revoked session must stay dead, and the
    // read must not have slid its window.
    let sessions = db.store().scoped(scope).sessions();
    assert!(
        sessions
            .get(&session, idle_ttl / 2, idle_ttl)
            .await
            .expect("read")
            .is_none(),
        "a revoked session must never resolve, slide or no slide"
    );
    let idle_after = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT (EXTRACT(EPOCH FROM idle_expires_at) * 1000000)::bigint FROM sessions \
         WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
    )
    .bind(session.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("read idle window");
    assert_eq!(
        idle_after,
        Some(idle_ttl),
        "a revoked session's idle window must never be pushed forward by a resolve"
    );
}

/// Count families that are the exact orphan the fix forbids: a SESSION-BOUND
/// (non-offline) family whose OWN `revoked_at` is still NULL while the session it is
/// bound to is dead (revoked, ended, or superseded). After a session revoke has
/// completed this MUST be zero: every session-bound family for that session is either
/// revoked with it (the open won the race, the cascade then reached it) or was never
/// opened at all (the open lost the race and refused with `SessionNotLive`). A non-zero
/// count is a redeemable refresh family that outlived its logout.
async fn orphaned_live_families(db: &TestDatabase, scope: Scope) -> i64 {
    sqlx::query(
        "SELECT count(*) AS c FROM refresh_families f \
         JOIN sessions s ON s.id = f.session_ref \
         AND s.tenant_id = f.tenant_id AND s.environment_id = f.environment_id \
         WHERE f.tenant_id = $1 AND f.environment_id = $2 \
         AND f.offline = false AND f.revoked_at IS NULL \
         AND (s.revoked_at IS NOT NULL OR s.ended_at IS NOT NULL \
              OR s.superseded_by IS NOT NULL)",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("count orphaned live families")
    .get("c")
}

/// The heart of issue #32: under TRUE concurrency, a storm of session-bound family
/// opens racing one session revoke must never leave a live family bound to a dead
/// session. This is the reviewer's storm distilled to an invariant, run against real
/// Postgres over many rounds so a regression shows.
///
/// Each round seeds one live session and `OPENS` session-bound grants, then fires all
/// `OPENS` family opens PLUS one revoke of that session concurrently, on a pool wide
/// enough that they genuinely overlap (the default 10-connection pool would serialize
/// them and hide the race). After the dust settles the invariant is asserted: ZERO
/// orphaned live families for that revoked session. The FOR UPDATE row lock the open
/// takes on the bound session (PART 1) is what forces every open to serialize against
/// the revoke's `UPDATE sessions`, so an open either commits before the revoke (its
/// family is then reached by the cascade) or re-reads the dead session and refuses.
///
/// The EXISTS-only guard the previous fix shipped passes the sequential tests but
/// FAILS this one: removing/weakening the FOR UPDATE lets an open's snapshot see the
/// session live and insert a family the concurrent revoke's cascade cannot yet see,
/// leaving orphans (the reviewer measured 237 across 30 rounds that way).
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[allow(clippy::too_many_lines)]
async fn a_storm_of_session_bound_opens_never_orphans_a_family_onto_a_revoked_session() {
    // >= 24 concurrent opens vs 1 concurrent revoke (the reviewer's storm width), over
    // >= 20 rounds (enough that a regression accumulates visible orphans).
    const OPENS: usize = 24;
    const ROUNDS: usize = 20;

    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = UserId::generate(&env, &scope).to_string();

    // One shared, wide pool so the storm actually overlaps; comfortably under the
    // server's default 100-connection cap even with the revoke contending.
    let store = db.app_store_with_pool(40).await;

    let mut total_opened: i64 = 0;
    for round in 0..ROUNDS {
        let session = create_session(&db, &env, scope, &subject, None).await;
        // One session-bound grant per concurrent opener (a family roots at a grant).
        let mut grants = Vec::with_capacity(OPENS);
        for _ in 0..OPENS {
            grants.push(seed_grant(&db, &env, scope, &subject, &session).await);
        }

        let mut tasks = tokio::task::JoinSet::new();
        for grant in grants {
            let store = store.clone();
            let db = db.clone();
            let subject = subject.clone();
            tasks.spawn(async move {
                let env = Env::system();
                let family_id = RefreshFamilyId::generate(&env, &scope);
                let jti = RefreshTokenId::generate(&env, &scope);
                let digest = refresh_token_digest(&format!("ira_rt_{jti}~storm"));
                store
                    .scoped(scope)
                    .acting(db.test_actor(&env), CorrelationId::generate(&env))
                    .refresh()
                    .issue(
                        &env,
                        NewRefreshFamily {
                            family_id: &family_id,
                            token_jti: &jti,
                            token_digest: &digest,
                            grant_id: &grant,
                            subject: &subject,
                            client_id: "cli_storm",
                            scope: Some("openid"),
                            auth_methods: "pwd",
                            auth_time_unix_micros: None,
                            offline: false,
                            created_at_unix_micros: 0,
                            idle_expires_at_unix_micros: FAR_FUTURE_MICROS,
                            absolute_expires_at_unix_micros: FAR_FUTURE_MICROS,
                            dpop_jkt: None,
                        },
                    )
                    .await
                    .expect("open family in the storm")
            });
        }
        // The lone revoke, fired into the same overlap window as the opens.
        {
            let store = store.clone();
            let db = db.clone();
            tasks.spawn(async move {
                let env = Env::system();
                store
                    .scoped(scope)
                    .acting(db.test_actor(&env), CorrelationId::generate(&env))
                    .sessions()
                    .revoke(&env, &session, SessionEndCause::Revoked, false, None)
                    .await
                    .expect("revoke the session mid-storm");
                RefreshFamilyOpenOutcome::Opened
            });
        }
        while let Some(joined) = tasks.join_next().await {
            joined.expect("a storm task panicked");
        }

        // The session really is dead now, so the invariant is meaningful.
        let revoked: bool = sqlx::query(
            "SELECT revoked_at IS NOT NULL AS r FROM sessions \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
        )
        .bind(session.to_string())
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .fetch_one(db.owner_pool())
        .await
        .expect("read session state")
        .get("r");
        assert!(
            revoked,
            "round {round}: the storm's revoke must have landed"
        );

        // THE INVARIANT: no live session-bound family survives the revoked session.
        assert_eq!(
            orphaned_live_families(&db, scope).await,
            0,
            "round {round}: a session-bound family outlived its revoked session",
        );

        total_opened += sqlx::query(
            "SELECT count(*) AS c FROM refresh_families \
             WHERE session_ref = $1 AND tenant_id = $2 AND environment_id = $3",
        )
        .bind(session.to_string())
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .fetch_one(db.owner_pool())
        .await
        .expect("count families opened this round")
        .get::<i64, _>("c");
    }

    // Guard against a silent no-op: across the whole run the storm must have actually
    // WON some opens (families that raced ahead of the revoke and were then cascaded),
    // otherwise every open merely lost and the invariant would hold vacuously.
    assert!(
        total_opened > 0,
        "the storm never opened a single family across {ROUNDS} rounds -- \
         the test is not exercising the race it claims to",
    );
}
