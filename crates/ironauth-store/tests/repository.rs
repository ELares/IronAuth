// SPDX-License-Identifier: MIT OR Apache-2.0

//! Repository round-trip and non-recycling, against a real database.

use std::collections::HashSet;

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    AuthorizationCodeId, ClientId, CorrelationId, GrantId, IssueCode, NewPolicyDecisionTrace,
    NewRefreshFamily, NewSession, NewTokenSizeEvent, PolicyDecisionInputs,
    PolicyDecisionTraceQuery, PolicyKind, PolicyOutcome, PolicyTraceSignal, RefreshFamilyId,
    RefreshTokenId, Scope, SessionId, StoreError, TokenSizeKind, refresh_token_digest,
};

#[tokio::test]
async fn create_get_list_delete_round_trip() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // Reads need no actor; writes go through an acting context.
    let reader = db.store().scoped(scope).clients();
    let actor = db.test_actor(&env);
    let writer = db
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(&env))
        .clients();

    // Create returns a typed identifier that round-trips through the scoped
    // parser (the request-layer boundary).
    let id = writer.create(&env, "acme web").await.expect("create");
    let parsed = reader.parse_id(&id.to_string()).expect("parse in scope");
    assert_eq!(parsed, id);
    assert_eq!(id.scope(), scope, "the identifier embeds its scope");

    // Get.
    let record = reader.get(&id).await.expect("get");
    assert_eq!(record.id, id);
    assert_eq!(record.display_name, "acme web");

    // List.
    let all = reader.list().await.expect("list");
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].id, id);

    // Delete, then the row is gone and the outcome is the uniform not-found.
    writer.delete(&env, &id).await.expect("delete");
    assert!(matches!(reader.get(&id).await, Err(StoreError::NotFound)));
    assert!(matches!(
        writer.delete(&env, &id).await,
        Err(StoreError::NotFound)
    ));
    assert!(reader.list().await.expect("list").is_empty());
}

#[tokio::test]
async fn identifiers_are_never_recycled_after_deletion() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let writer = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients();

    // Create then delete many; remember every identifier ever issued.
    let mut ever_issued = HashSet::new();
    for _ in 0..200 {
        let id = writer.create(&env, "ephemeral").await.expect("create");
        writer.delete(&env, &id).await.expect("delete");
        assert!(
            ever_issued.insert(id.to_string()),
            "an identifier was issued twice"
        );
    }

    // A fresh batch never collides with any deleted identifier: no serial
    // reuse, no recycled-identifier leakage.
    for _ in 0..200 {
        let id = writer.create(&env, "fresh").await.expect("create");
        assert!(
            !ever_issued.contains(&id.to_string()),
            "a deleted identifier was recycled"
        );
    }
}

/// A management list at the hard cap keeps its has-next sentinel: with
/// `HARD_CAP + 1` rows present, a fetch of `HARD_CAP + 1` (the page size at the
/// cap, plus one for the sentinel) returns all `HARD_CAP + 1`. Before the store
/// clamped the fetch to `HARD_CAP + 1` (rather than `HARD_CAP`), the sentinel was
/// dropped and the final page hidden.
#[tokio::test]
async fn management_list_at_the_hard_cap_keeps_the_has_next_sentinel() {
    use ironauth_store::{MANAGEMENT_LIST_HARD_CAP, ManagementKeyId};

    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // Insert HARD_CAP + 1 credentials as the owner (a superuser, so it bypasses
    // row-level security), in one bulk statement via UNNEST.
    let n = usize::try_from(MANAGEMENT_LIST_HARD_CAP).expect("cap fits usize") + 1;
    let ids: Vec<String> = (0..n)
        .map(|_| ManagementKeyId::generate(&env, &scope).to_string())
        .collect();
    let tenants = vec![scope.tenant().to_string(); n];
    let environments = vec![scope.environment().to_string(); n];
    let hashes: Vec<String> = (0..n).map(|i| format!("hash-{i}")).collect();
    let names: Vec<String> = (0..n).map(|i| format!("key-{i}")).collect();
    sqlx::query(
        "INSERT INTO management_credentials \
         (id, tenant_id, environment_id, key_hash, display_name) \
         SELECT * FROM UNNEST($1::text[], $2::text[], $3::text[], $4::text[], $5::text[])",
    )
    .bind(ids)
    .bind(tenants)
    .bind(environments)
    .bind(hashes)
    .bind(names)
    .execute(db.owner_pool())
    .await
    .expect("bulk insert credentials");

    // The admin layer fetches page_size + 1; at a page size of HARD_CAP that is
    // HARD_CAP + 1. The store must return all of them (the extra row is the
    // sentinel that tells the admin layer a further page exists).
    let rows = db
        .control_store()
        .management()
        .credentials(scope)
        .list(MANAGEMENT_LIST_HARD_CAP + 1, None)
        .await
        .expect("list at the hard cap");
    assert_eq!(
        rows.len(),
        n,
        "the has-next sentinel survives at a page size equal to the hard cap"
    );
}

/// Scope-aware consent (issue #196): `granted_ref` returns the granted scope, and a
/// re-consent to a BROADER scope UPSERTs the scope in place, keeping the row's
/// ORIGINAL id rather than inserting a second row or dropping the broadened scope.
#[tokio::test]
async fn consent_grant_upserts_the_scope_and_keeps_the_original_id() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // The consents table keys on (subject, client_id) text with no FK to users or
    // clients, so literal ids exercise the grant/read contract directly.
    let subject = "usr_example-subject";
    let client_id = "cli_example-client";

    // A first consent for a NARROW scope records the granted scope and returns its id.
    let first = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .consents()
        .grant(&env, subject, client_id, Some("openid"))
        .await
        .expect("first grant");
    let recorded = db
        .store()
        .scoped(scope)
        .consents()
        .granted_ref(subject, client_id)
        .await
        .expect("granted_ref read")
        .expect("a consent is recorded");
    assert_eq!(recorded.id, first.to_string(), "granted_ref returns the id");
    assert_eq!(
        recorded.granted_scope.as_deref(),
        Some("openid"),
        "granted_ref returns the granted scope"
    );

    // Re-consent to a BROADER scope UPDATEs granted_scope in place and returns the
    // ORIGINAL row id (the upsert keeps it), not a fresh id or a second row.
    let second = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .consents()
        .grant(&env, subject, client_id, Some("openid profile email"))
        .await
        .expect("re-grant");
    assert_eq!(
        second, first,
        "the upsert returns the original consent id on re-consent"
    );
    let updated = db
        .store()
        .scoped(scope)
        .consents()
        .granted_ref(subject, client_id)
        .await
        .expect("granted_ref read")
        .expect("a consent is recorded");
    assert_eq!(
        updated.id,
        first.to_string(),
        "the row keeps its original id"
    );
    assert_eq!(
        updated.granted_scope.as_deref(),
        Some("openid profile email"),
        "the broadened scope is persisted rather than dropped"
    );
}

/// Re-consent audit attribution (issue #196): the `consent.grant` audit row's
/// `target_id` joins to the ACTUAL `consents` row on BOTH a first insert and a
/// scope-broadening re-consent. The upsert's UPDATE branch keeps the row's ORIGINAL
/// id, so a freshly generated (never-persisted) audit target would be a phantom an
/// investigator could not pivot from; this proves the audit target is the real id.
#[tokio::test]
async fn consent_grant_audit_target_joins_the_persisted_consent_row() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let subject = "usr_example-subject";
    let client_id = "cli_example-client";

    // A first consent (narrow), then a scope-BROADENING re-consent (the
    // security-relevant event): the second takes the upsert's UPDATE branch and keeps
    // the original id, which is exactly where a phantom audit target would show up.
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .consents()
        .grant(&env, subject, client_id, Some("openid"))
        .await
        .expect("first grant");
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .consents()
        .grant(&env, subject, client_id, Some("openid profile email"))
        .await
        .expect("re-grant");

    // Exactly two consent.grant audit rows, and EACH one's target_id must join to a
    // real consents row (the broaden's target is NOT a phantom fresh id).
    let audit = db
        .store()
        .scoped(scope)
        .audit()
        .list()
        .await
        .expect("audit");
    let grants: Vec<_> = audit
        .iter()
        .filter(|row| row.action == "consent.grant")
        .collect();
    assert_eq!(
        grants.len(),
        2,
        "each grant writes exactly one consent.grant audit row"
    );
    for row in grants {
        assert_eq!(row.target_kind, "con", "the audit target is a consent id");
        let joined: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM consents \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
        )
        .bind(&row.target_id)
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .fetch_one(db.owner_pool())
        .await
        .expect("count consents by audit target id");
        assert_eq!(
            joined, 1,
            "the consent.grant audit target_id ({}) joins to exactly one consents row",
            row.target_id
        );
    }

    // And the upsert updated in place: exactly ONE consents row exists, so the
    // broaden's audit target is the same row the first grant's target named.
    let consent_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM consents")
        .fetch_one(db.owner_pool())
        .await
        .expect("count consents");
    assert_eq!(
        consent_rows, 1,
        "the re-consent updated in place rather than inserting a second row"
    );
}

/// A fixed revocation instant (microseconds since the Unix epoch), passed to
/// `revoke` from the caller's clock seam (never `SystemTime` inside the store).
const REVOKE_AT_MICROS: i64 = 1_800_000_000_000_000;

/// Revoke makes a grant ABSENT to the gate and is idempotent (issue #88): after a
/// revoke, `granted_ref` returns `None` (the revoked grant no longer satisfies the
/// consent gate) and `list_for_subject` excludes it; revoking an already-revoked or
/// an absent grant is a no-op SUCCESS.
#[tokio::test]
async fn consent_revoke_makes_a_grant_absent_and_is_idempotent() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let subject = "usr_example-subject";
    let client_id = "cli_example-client";

    // Grant, then confirm it is visible to both the gate read and the list.
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .consents()
        .grant(&env, subject, client_id, Some("openid profile"))
        .await
        .expect("grant");
    assert!(
        db.store()
            .scoped(scope)
            .consents()
            .granted_ref(subject, client_id)
            .await
            .expect("granted_ref")
            .is_some(),
        "the active grant satisfies the gate read"
    );
    let active = db
        .store()
        .scoped(scope)
        .consents()
        .list_for_subject(subject)
        .await
        .expect("list_for_subject");
    assert_eq!(active.len(), 1, "the active grant is listed");
    assert_eq!(active[0].client_id, client_id);
    assert_eq!(active[0].granted_scope.as_deref(), Some("openid profile"));

    // Revoke: the grant becomes absent to the gate and drops out of the list.
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .consents()
        .revoke(&env, subject, client_id, REVOKE_AT_MICROS)
        .await
        .expect("revoke");
    assert!(
        db.store()
            .scoped(scope)
            .consents()
            .granted_ref(subject, client_id)
            .await
            .expect("granted_ref after revoke")
            .is_none(),
        "a revoked grant is treated as absent by the gate read"
    );
    assert!(
        db.store()
            .scoped(scope)
            .consents()
            .list_for_subject(subject)
            .await
            .expect("list after revoke")
            .is_empty(),
        "a revoked grant is excluded from the active list"
    );

    // Idempotent: revoking again (already revoked) and revoking an absent grant both
    // succeed as no-ops.
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .consents()
        .revoke(&env, subject, client_id, REVOKE_AT_MICROS)
        .await
        .expect("revoking an already-revoked grant is a no-op success");
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .consents()
        .revoke(&env, subject, "cli_never-granted", REVOKE_AT_MICROS)
        .await
        .expect("revoking an absent grant is a no-op success");
}

/// A real revocation writes exactly one `consent.revoke` audit row targeting the
/// revoked consent row; an idempotent no-op revoke writes NONE (issue #88).
#[tokio::test]
async fn consent_revoke_audits_only_a_real_revocation() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let subject = "usr_example-subject";
    let client_id = "cli_example-client";

    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .consents()
        .grant(&env, subject, client_id, Some("openid"))
        .await
        .expect("grant");
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .consents()
        .revoke(&env, subject, client_id, REVOKE_AT_MICROS)
        .await
        .expect("revoke");
    // A second (already-revoked) revoke must NOT write another audit row.
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .consents()
        .revoke(&env, subject, client_id, REVOKE_AT_MICROS)
        .await
        .expect("no-op revoke");

    let audit = db
        .store()
        .scoped(scope)
        .audit()
        .list()
        .await
        .expect("audit");
    let revokes: Vec<_> = audit
        .iter()
        .filter(|row| row.action == "consent.revoke")
        .collect();
    assert_eq!(
        revokes.len(),
        1,
        "only the real revocation writes a consent.revoke audit row"
    );
    assert_eq!(
        revokes[0].target_kind, "con",
        "the revoke audit targets a consent id"
    );
    let joined: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM consents \
         WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
    )
    .bind(&revokes[0].target_id)
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("count consents by audit target id");
    assert_eq!(
        joined, 1,
        "the revoke audit target joins to the consent row"
    );
}

/// Re-granting a previously REVOKED consent REACTIVATES the same row (issue #88): the
/// grant upsert clears `revoked_at`, so a fresh grant after a revoke is honored rather
/// than staying revoked and re-prompting forever.
#[tokio::test]
async fn re_grant_after_revoke_reactivates_the_same_consent_row() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let subject = "usr_example-subject";
    let client_id = "cli_example-client";

    let first = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .consents()
        .grant(&env, subject, client_id, Some("openid"))
        .await
        .expect("first grant");
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .consents()
        .revoke(&env, subject, client_id, REVOKE_AT_MICROS)
        .await
        .expect("revoke");

    // Re-grant: the same row is reactivated (revoked_at cleared) and keeps its id.
    let second = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .consents()
        .grant(&env, subject, client_id, Some("openid profile"))
        .await
        .expect("re-grant after revoke");
    assert_eq!(
        second, first,
        "the re-grant reactivates the original consent row"
    );
    let recorded = db
        .store()
        .scoped(scope)
        .consents()
        .granted_ref(subject, client_id)
        .await
        .expect("granted_ref")
        .expect("the reactivated grant is visible again");
    assert_eq!(recorded.id, first.to_string(), "the row keeps its id");
    assert_eq!(
        recorded.granted_scope.as_deref(),
        Some("openid profile"),
        "the re-grant records the new scope on the reactivated row"
    );
    // Exactly one consents row: the re-grant updated in place rather than inserting.
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM consents")
        .fetch_one(db.owner_pool())
        .await
        .expect("count consents");
    assert_eq!(rows, 1, "the re-grant updated in place");
}

/// The `first_party` classification round-trips on `ClientRecord` (issue #88): it
/// defaults to false on create and reads back true once the control plane sets it.
#[tokio::test]
async fn first_party_round_trips_on_the_client_record() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let id = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .create(&env, "acme web")
        .await
        .expect("create");
    let record = db
        .store()
        .scoped(scope)
        .clients()
        .get(&id)
        .await
        .expect("get");
    assert!(
        !record.first_party,
        "a client is third-party (first_party = false) by default"
    );

    // The control plane classifies the client as first-party (PR2 only stores and
    // selects the column; the admin surface lands later, so set it directly here).
    sqlx::query("UPDATE clients SET first_party = true WHERE id = $1")
        .bind(id.to_string())
        .execute(db.owner_pool())
        .await
        .expect("classify first-party");
    let record = db
        .store()
        .scoped(scope)
        .clients()
        .get(&id)
        .await
        .expect("get after classify");
    assert!(
        record.first_party,
        "the first-party classification reads back on ClientRecord"
    );
    // It also round-trips through the list read.
    let listed = db
        .store()
        .scoped(scope)
        .clients()
        .list()
        .await
        .expect("list");
    assert!(
        listed.iter().any(|c| c.id == id && c.first_party),
        "the list read carries first_party too"
    );
}

/// The revoke write and the active-list read are RLS-scope isolated (issue #88): a
/// grant in one scope is invisible and unrevocable from another scope.
#[tokio::test]
async fn consent_revoke_and_list_are_cross_scope_isolated() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;

    let subject = "usr_example-subject";
    let client_id = "cli_example-client";

    // Grant in scope A.
    db.store()
        .scoped(scope_a)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .consents()
        .grant(&env, subject, client_id, Some("openid"))
        .await
        .expect("grant in scope A");

    // Scope B cannot see it: the active list is empty and a revoke from scope B is a
    // no-op that does NOT touch scope A's grant (row-level security hides the row).
    assert!(
        db.store()
            .scoped(scope_b)
            .consents()
            .list_for_subject(subject)
            .await
            .expect("list in scope B")
            .is_empty(),
        "scope B does not see scope A's grant"
    );
    db.store()
        .scoped(scope_b)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .consents()
        .revoke(&env, subject, client_id, REVOKE_AT_MICROS)
        .await
        .expect("cross-scope revoke is a no-op success");

    // Scope A's grant is untouched: still active and still listed.
    assert!(
        db.store()
            .scoped(scope_a)
            .consents()
            .granted_ref(subject, client_id)
            .await
            .expect("granted_ref in scope A")
            .is_some(),
        "a cross-scope revoke does not revoke scope A's grant"
    );
    assert_eq!(
        db.store()
            .scoped(scope_a)
            .consents()
            .list_for_subject(subject)
            .await
            .expect("list in scope A")
            .len(),
        1,
        "scope A still lists its active grant"
    );
}

// ===========================================================================
// The consent-revoke refresh-family cascade (issue #88, PR 5).
//
// Revoking a consent stamps the grant revoked AND, in the SAME transaction,
// revokes the (subject, client) refresh families (both session-bound AND offline,
// the point-of-difference from a session logout). These pin the scope-tightness
// (BOTH subject and client bound), the offline inclusion, the flip gating, and the
// single-audit contract.
// ===========================================================================

/// A far-future family expiry (year 2100) in epoch microseconds: an absolute/idle cap
/// far enough out that a seeded family stays live until a test revokes it.
const FAMILY_FAR_FUTURE_MICROS: i64 = 4_102_444_800_000_000;

/// Issue an authorization code and its grant in `scope` for `subject`, carrying an
/// optional `session_ref`, and return the grant id. A family rooted at this grant reads
/// the grant's `session_ref`, so a SESSION-BOUND family binds to the live session.
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
                browserless: false,
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
                expires_at_micros: FAMILY_FAR_FUTURE_MICROS,
                created_at_micros: 0,
            },
        )
        .await
        .expect("issue code");
    grant_id
}

/// Create a LIVE session in `scope` for `subject`, so a session-bound family opened
/// against it passes the live-session guard (issue #32).
async fn create_live_session(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    subject: &str,
) -> SessionId {
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
                idle_expires_micros: FAMILY_FAR_FUTURE_MICROS,
                absolute_expires_micros: FAMILY_FAR_FUTURE_MICROS,
                user_agent: None,
                peer_ip: None,
            },
        )
        .await
        .expect("create session");
    id
}

/// Open a refresh-token family (generation 0) rooted at `grant_id`, for the given
/// `subject` and `client_id` string, session-bound or `offline_access`, and return its
/// id. The family carries the (subject, client) the consent cascade keys on.
async fn open_family(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    grant_id: &GrantId,
    subject: &str,
    client_id: &str,
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
                client_id,
                scope: Some("openid"),
                auth_methods: "pwd",
                auth_time_unix_micros: None,
                offline,
                created_at_unix_micros: 0,
                idle_expires_at_unix_micros: FAMILY_FAR_FUTURE_MICROS,
                absolute_expires_at_unix_micros: FAMILY_FAR_FUTURE_MICROS,
            },
        )
        .await
        .expect("open family");
    family_id
}

/// Whether the family `family` reads back revoked. Asserts the row EXISTS (the seeded
/// family opened), so a session-bound family that failed the liveness guard is caught.
async fn family_revoked(db: &TestDatabase, scope: Scope, family: &RefreshFamilyId) -> bool {
    let revoked_at: Option<i64> = sqlx::query_scalar(
        "SELECT (EXTRACT(EPOCH FROM revoked_at) * 1000000)::bigint FROM refresh_families \
         WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
    )
    .bind(family.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("the seeded family exists");
    revoked_at.is_some()
}

/// Revoking a consent cascades to the (subject, client) refresh families INCLUDING the
/// `offline_access` ones (issue #88): a consent withdrawal kills the offline families
/// too, the deliberate point-of-difference from a session logout (which spares them).
#[tokio::test]
async fn consent_revoke_cascades_to_subject_client_families_including_offline() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let subject = "usr_cascade-subject";
    let client_id = "cli_cascade-client";

    // The consent to revoke.
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .consents()
        .grant(&env, subject, client_id, Some("openid"))
        .await
        .expect("grant");

    // One session-bound and one offline_access family, both for (subject, client).
    let session = create_live_session(&db, &env, scope, subject).await;
    let bound_grant = seed_grant(&db, &env, scope, subject, Some(&session)).await;
    let bound = open_family(&db, &env, scope, &bound_grant, subject, client_id, false).await;
    let offline_grant = seed_grant(&db, &env, scope, subject, None).await;
    let offline = open_family(&db, &env, scope, &offline_grant, subject, client_id, true).await;
    assert!(
        !family_revoked(&db, scope, &bound).await,
        "bound family starts live"
    );
    assert!(
        !family_revoked(&db, scope, &offline).await,
        "offline family starts live"
    );

    let revocation = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .consents()
        .revoke(&env, subject, client_id, REVOKE_AT_MICROS)
        .await
        .expect("revoke");
    assert!(revocation.consent_revoked, "the consent flipped");
    assert_eq!(
        revocation.families_revoked, 2,
        "both the session-bound AND the offline_access family were revoked"
    );
    assert!(
        family_revoked(&db, scope, &bound).await,
        "the session-bound family is revoked"
    );
    assert!(
        family_revoked(&db, scope, &offline).await,
        "the offline_access family is revoked too (no offline filter, unlike a logout)"
    );
}

/// The cascade is SCOPE-TIGHT to the exact (subject, client) grant (issue #88, the
/// crux): a family for the SAME subject under a DIFFERENT client, and one for a
/// DIFFERENT subject under the SAME client, are BOTH left untouched. The WHERE binds
/// BOTH subject AND client, so it is neither subject-only (too broad) nor session-bound
/// (too narrow).
#[tokio::test]
async fn consent_revoke_cascade_is_scope_tight_to_subject_and_client() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let subject_a = "usr_subject-a";
    let subject_b = "usr_subject-b";
    let client_a = "cli_client-a";
    let client_b = "cli_client-b";

    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .consents()
        .grant(&env, subject_a, client_a, Some("openid"))
        .await
        .expect("grant");

    // The target family, plus two decoys that must survive.
    let g_target = seed_grant(&db, &env, scope, subject_a, None).await;
    let target = open_family(&db, &env, scope, &g_target, subject_a, client_a, true).await;
    let g_other_client = seed_grant(&db, &env, scope, subject_a, None).await;
    let other_client =
        open_family(&db, &env, scope, &g_other_client, subject_a, client_b, true).await;
    let g_other_subject = seed_grant(&db, &env, scope, subject_b, None).await;
    let other_subject = open_family(
        &db,
        &env,
        scope,
        &g_other_subject,
        subject_b,
        client_a,
        true,
    )
    .await;

    let revocation = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .consents()
        .revoke(&env, subject_a, client_a, REVOKE_AT_MICROS)
        .await
        .expect("revoke");
    assert_eq!(
        revocation.families_revoked, 1,
        "exactly the (subject_a, client_a) family is revoked"
    );
    assert!(
        family_revoked(&db, scope, &target).await,
        "the (subject_a, client_a) family is revoked"
    );
    assert!(
        !family_revoked(&db, scope, &other_client).await,
        "a family for the same subject under a DIFFERENT client is NOT revoked"
    );
    assert!(
        !family_revoked(&db, scope, &other_subject).await,
        "a family for a DIFFERENT subject under the same client is NOT revoked"
    );
}

/// An idempotent no-op revoke (an absent or already-revoked grant) runs NO cascade
/// (issue #88): the cascade is gated on the consent ACTUALLY flipping, so a family for
/// the (subject, client) is left untouched and no audit row is written.
#[tokio::test]
async fn consent_revoke_no_op_runs_no_cascade_and_writes_no_audit() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let subject = "usr_noop-subject";
    let client_id = "cli_noop-client";

    // A live family for (subject, client), but NO consent granted, so a revoke does not
    // flip anything and must not cascade.
    let grant = seed_grant(&db, &env, scope, subject, None).await;
    let family = open_family(&db, &env, scope, &grant, subject, client_id, true).await;

    let revocation = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .consents()
        .revoke(&env, subject, client_id, REVOKE_AT_MICROS)
        .await
        .expect("no-op revoke");
    assert!(
        !revocation.consent_revoked,
        "an absent grant does not flip (consent_revoked = false)"
    );
    assert_eq!(
        revocation.families_revoked, 0,
        "the gated cascade did not run for a revocation that did not happen"
    );
    assert!(
        !family_revoked(&db, scope, &family).await,
        "the family is untouched: the cascade is gated on the consent flip"
    );
    let audit = db
        .store()
        .scoped(scope)
        .audit()
        .list()
        .await
        .expect("audit");
    assert!(
        !audit.iter().any(|row| row.action == "consent.revoke"),
        "a no-op revoke writes no consent.revoke audit row"
    );
}

/// A real revocation with a family cascade writes EXACTLY ONE `consent.revoke` audit
/// row and NO per-family audit row (issue #88): the single consent event is the record,
/// matching the `refresh_family.revoke` precedent (no per-generation audit).
#[tokio::test]
async fn consent_revoke_cascade_writes_one_consent_audit_and_no_per_family_audit() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let subject = "usr_audit-subject";
    let client_id = "cli_audit-client";

    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .consents()
        .grant(&env, subject, client_id, Some("openid"))
        .await
        .expect("grant");
    let grant = seed_grant(&db, &env, scope, subject, None).await;
    let _family = open_family(&db, &env, scope, &grant, subject, client_id, true).await;

    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .consents()
        .revoke(&env, subject, client_id, REVOKE_AT_MICROS)
        .await
        .expect("revoke");

    let audit = db
        .store()
        .scoped(scope)
        .audit()
        .list()
        .await
        .expect("audit");
    assert_eq!(
        audit
            .iter()
            .filter(|row| row.action == "consent.revoke")
            .count(),
        1,
        "exactly one consent.revoke audit row for a real revocation"
    );
    assert_eq!(
        audit
            .iter()
            .filter(|row| row.action == "refresh_family.revoke")
            .count(),
        0,
        "the cascade writes NO per-family audit row"
    );
}

#[tokio::test]
async fn post_logout_redirect_uris_register_read_and_validate() {
    // RP-Initiated Logout (issue #33): a client's post_logout_redirect_uris are an
    // exact-match set the end_session endpoint checks against. Default empty, registered
    // wholesale, validated as registrable targets, and scope-fenced.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let reader = db.store().scoped(scope).clients();
    let writer = || {
        db.store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .clients()
    };

    let id = writer()
        .create(&env, "logout client")
        .await
        .expect("create");

    // Default: a fresh client registers NO post-logout redirect URIs.
    let record = reader.get(&id).await.expect("get");
    assert!(
        record.post_logout_redirect_uris.is_empty(),
        "a fresh client has an empty post-logout redirect set"
    );

    // Register a set; it reads back verbatim (exact-string, no normalization).
    writer()
        .register_post_logout_redirect_uris(
            &env,
            &id,
            &["https://client.test/after", "https://client.test/home"],
        )
        .await
        .expect("register post-logout uris");
    let record = reader.get(&id).await.expect("get");
    assert_eq!(
        record.post_logout_redirect_uris,
        vec![
            "https://client.test/after".to_owned(),
            "https://client.test/home".to_owned()
        ],
        "the registered set reads back exactly"
    );

    // Re-registering REPLACES the set wholesale.
    writer()
        .register_post_logout_redirect_uris(&env, &id, &["https://client.test/only"])
        .await
        .expect("re-register");
    assert_eq!(
        reader
            .get(&id)
            .await
            .expect("get")
            .post_logout_redirect_uris,
        vec!["https://client.test/only".to_owned()]
    );

    // A malformed (non-registrable) target rejects the WHOLE set; nothing is stored.
    assert!(matches!(
        writer()
            .register_post_logout_redirect_uris(
                &env,
                &id,
                &["https://client.test/good", "javascript:alert(1)"]
            )
            .await,
        Err(StoreError::InvalidRedirectUri)
    ));
    assert_eq!(
        reader
            .get(&id)
            .await
            .expect("get")
            .post_logout_redirect_uris,
        vec!["https://client.test/only".to_owned()],
        "a rejected registration leaves the prior set untouched"
    );

    // A client id from another scope is the uniform not-found (never a cross-tenant write).
    let other_scope = db.seed_scope(&env).await;
    let foreign = db
        .store()
        .scoped(other_scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .create(&env, "other-tenant client")
        .await
        .expect("create foreign");
    assert!(matches!(
        writer()
            .register_post_logout_redirect_uris(&env, &foreign, &["https://client.test/x"])
            .await,
        Err(StoreError::NotFound)
    ));
}

#[tokio::test]
async fn frontchannel_logout_register_read_and_validate() {
    // Front-Channel Logout (issue #39): a client's frontchannel_logout_uri and
    // session_required flag are the per-client opt-in the end_session flow reads.
    // Default absent, registered as one https URI, https-validated, clearable, and
    // scope-fenced.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let reader = db.store().scoped(scope).clients();
    let writer = || {
        db.store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .clients()
    };

    let id = writer()
        .create(&env, "frontchannel client")
        .await
        .expect("create");

    // Default: a fresh client has registered no front-channel logout URI, and its
    // session_required flag is false.
    let record = reader.get(&id).await.expect("get");
    assert_eq!(record.frontchannel_logout_uri, None);
    assert!(!record.frontchannel_logout_session_required);

    // Register a URI with session_required; it reads back verbatim.
    writer()
        .register_frontchannel_logout(&env, &id, Some("https://rp.test/frontchannel"), true)
        .await
        .expect("register frontchannel logout");
    let record = reader.get(&id).await.expect("get");
    assert_eq!(
        record.frontchannel_logout_uri.as_deref(),
        Some("https://rp.test/frontchannel")
    );
    assert!(record.frontchannel_logout_session_required);

    // A non-https URI rejects the registration; the prior value is untouched.
    assert!(matches!(
        writer()
            .register_frontchannel_logout(&env, &id, Some("http://rp.test/insecure"), false)
            .await,
        Err(StoreError::InvalidRedirectUri)
    ));
    let record = reader.get(&id).await.expect("get");
    assert_eq!(
        record.frontchannel_logout_uri.as_deref(),
        Some("https://rp.test/frontchannel"),
        "a rejected registration leaves the prior value untouched"
    );

    // Security hardening (issue #89): the origin of a registered URI becomes a
    // frame-src source on the front-channel logout page, so an authority carrying a
    // space, a `;`, a control character, or userinfo (which could smuggle extra CSP
    // sources or directives) is refused BEFORE it is stored. The prior value stands.
    for smuggle in [
        "https://rp.test frame-src *",
        "https://rp.test;script-src 'unsafe-inline'",
        "https://rp.test\u{0009}/fc",
        "https://user:pass@rp.test/fc",
        "https://",
    ] {
        assert!(
            matches!(
                writer()
                    .register_frontchannel_logout(&env, &id, Some(smuggle), false)
                    .await,
                Err(StoreError::InvalidRedirectUri)
            ),
            "a malformed https authority is rejected: {smuggle:?}"
        );
    }
    let record = reader.get(&id).await.expect("get");
    assert_eq!(
        record.frontchannel_logout_uri.as_deref(),
        Some("https://rp.test/frontchannel"),
        "a rejected malformed registration leaves the prior value untouched"
    );

    // Passing None clears the registration wholesale.
    writer()
        .register_frontchannel_logout(&env, &id, None, false)
        .await
        .expect("clear frontchannel logout");
    let record = reader.get(&id).await.expect("get");
    assert_eq!(record.frontchannel_logout_uri, None);
    assert!(!record.frontchannel_logout_session_required);

    // A client id from another scope is the uniform not-found.
    let other_scope = db.seed_scope(&env).await;
    let foreign = db
        .store()
        .scoped(other_scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .create(&env, "other-tenant client")
        .await
        .expect("create foreign");
    assert!(matches!(
        writer()
            .register_frontchannel_logout(&env, &foreign, Some("https://rp.test/x"), false)
            .await,
        Err(StoreError::NotFound)
    ));
}

const TRACE_RETENTION_MICROS: i64 = 7 * 24 * 60 * 60 * 1_000_000;

#[tokio::test]
async fn policy_decision_traces_round_trip_and_filter() {
    // The M9 flow inspector sink (issue #91): record the three traced policy decisions and read
    // them back, newest first, filtered by policy and subject, with the redacted safe field
    // projection round-tripping through the jsonb column.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let traces = db.store().scoped(scope).policy_decision_traces();

    // A step up trace for one subject.
    traces
        .record(
            &env,
            TRACE_RETENTION_MICROS,
            &NewPolicyDecisionTrace {
                policy: PolicyKind::StepUp,
                subject: Some("usr_alice".to_owned()),
                outcome: PolicyOutcome::StepUpRequired,
                reason: Some("acr_unmet".to_owned()),
                inputs: PolicyDecisionInputs::StepUp {
                    required_acr: Some("urn:ironauth:acr:mfa".to_owned()),
                    achieved_acr: "urn:ironauth:acr:pwd".to_owned(),
                    max_auth_age_secs: Some(300),
                    auth_age_secs: Some(9000),
                    acr_unmet: true,
                    age_lapsed: false,
                },
            },
        )
        .await
        .expect("record step up trace");

    // A risk trace for the SAME subject, with enumerated signals.
    traces
        .record(
            &env,
            TRACE_RETENTION_MICROS,
            &NewPolicyDecisionTrace {
                policy: PolicyKind::Risk,
                subject: Some("usr_alice".to_owned()),
                outcome: PolicyOutcome::Deny,
                reason: Some("block".to_owned()),
                inputs: PolicyDecisionInputs::Risk {
                    level: "high".to_owned(),
                    signals: vec![PolicyTraceSignal {
                        name: "new_device".to_owned(),
                        level: "med".to_owned(),
                    }],
                },
            },
        )
        .await
        .expect("record risk trace");

    // A claim mapping trace for NO subject (evaluated before provisioning), another subject key.
    traces
        .record(
            &env,
            TRACE_RETENTION_MICROS,
            &NewPolicyDecisionTrace {
                policy: PolicyKind::ClaimMapping,
                subject: None,
                outcome: PolicyOutcome::Satisfied,
                reason: None,
                inputs: PolicyDecisionInputs::ClaimMapping {
                    connector: "octa".to_owned(),
                    mapped_trait_count: Some(3),
                    failure_kind: None,
                },
            },
        )
        .await
        .expect("record claim mapping trace");

    // Newest first over the whole scope: three rows, most recent (the claim mapping) first.
    let all = traces
        .query(PolicyDecisionTraceQuery {
            newest_first: true,
            ..Default::default()
        })
        .await
        .expect("query all");
    assert_eq!(all.len(), 3, "all three traces are readable");
    assert_eq!(all[0].policy, "claim_mapping", "newest first ordering");

    // Filter by policy narrows to the one risk trace, with its signals in the jsonb.
    let risk = traces
        .query(PolicyDecisionTraceQuery {
            policy: Some("risk"),
            newest_first: true,
            ..Default::default()
        })
        .await
        .expect("query risk");
    assert_eq!(risk.len(), 1, "the policy filter narrows to risk");
    assert_eq!(risk[0].outcome, "deny");
    assert!(
        risk[0].decision_inputs_json.contains("new_device"),
        "the redacted safe field projection round-trips through jsonb"
    );

    // Filter by subject narrows to the two traces bound to usr_alice (never the subjectless one).
    let alice = traces
        .query(PolicyDecisionTraceQuery {
            subject: Some("usr_alice"),
            ..Default::default()
        })
        .await
        .expect("query alice");
    assert_eq!(
        alice.len(),
        2,
        "the subject filter narrows to alice's traces"
    );
}

#[tokio::test]
async fn token_size_events_round_trip() {
    // The one materialized operational warning (issue #91): record two oversized token events and
    // read them back newest first for the M9 warnings read.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let events = db.store().scoped(scope).token_size_events();

    for byte_size in [4096_i64, 5120] {
        events
            .record(
                &env,
                TRACE_RETENTION_MICROS,
                NewTokenSizeEvent {
                    token_type: TokenSizeKind::IdToken,
                    byte_size,
                    claim_count: Some(40),
                    client_id: "cli_bloat",
                },
            )
            .await
            .expect("record token size event");
    }

    let recent = events.recent(50).await.expect("read recent");
    assert_eq!(recent.len(), 2, "both events are readable");
    assert!(
        recent.iter().all(|event| event.client_id == "cli_bloat"),
        "the events carry the non secret client id"
    );
    assert!(
        recent.iter().any(|event| event.byte_size == 5120),
        "the byte size round-trips"
    );
}
