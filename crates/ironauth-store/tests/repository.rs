// SPDX-License-Identifier: MIT OR Apache-2.0

//! Repository round-trip and non-recycling, against a real database.

use std::collections::HashSet;
use std::time::{Duration, UNIX_EPOCH};

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    AuthorizationCodeId, ClientId, CorrelationId, GrantId, IssueCode, NewPolicyDecisionTrace,
    NewRefreshFamily, NewSession, NewTokenSizeEvent, PolicyDecisionInputs,
    PolicyDecisionTraceQuery, PolicyKind, PolicyOutcome, PolicyTraceSignal, RefreshFamilyId,
    RefreshTokenId, Scope, SessionId, StoreError, TokenSizeEventsRepo, TokenSizeKind,
    TokenSizeReason, refresh_token_digest,
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
                org_id: None,
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
                dpop_jkt: None,
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
                    reason: None,
                    audience: None,
                    organization_id: None,
                    permission_count: None,
                    permission_status: None,
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
    // An ID-token bloat event leaves all five issue #98 budget columns NULL, which is what
    // makes "not a permission budget event" readable off the row itself.
    assert!(
        recent.iter().all(|event| event.reason.is_none()
            && event.audience.is_none()
            && event.organization_id.is_none()
            && event.permission_count.is_none()
            && event.permission_status.is_none()),
        "a bloat event records no budget dimension"
    );
}

#[tokio::test]
async fn token_size_event_budget_columns_round_trip() {
    // The issue #98 permission-budget dimensions on the same sink (migration 0095): all five
    // columns are WRITTEN and READ BACK, and none of them is a default that happens to look
    // right. The values are chosen so a crossed or defaulted column fails: the two strings
    // are not substrings of each other, the count is not the byte size, and this is the FIRST
    // row in the product recorded against `TokenSizeKind::AccessToken` (the variant and the
    // 0073 CHECK that admits it have both existed unconstructed since issue #91).
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let events = db.store().scoped(scope).token_size_events();

    events
        .record(
            &env,
            TRACE_RETENTION_MICROS,
            NewTokenSizeEvent {
                token_type: TokenSizeKind::AccessToken,
                byte_size: 9001,
                claim_count: None,
                client_id: "cli_budget",
                reason: Some(TokenSizeReason::BudgetOverflowCount),
                audience: Some("https://api.example.com/orders"),
                organization_id: Some("org_budget"),
                permission_count: Some(412),
                permission_status: Some("pdp_required"),
            },
        )
        .await
        .expect("record a permission budget event");

    let recent = events.recent(50).await.expect("read recent");
    assert_eq!(recent.len(), 1, "the budget event is readable");
    let event = &recent[0];
    assert_eq!(
        event.token_type, "access_token",
        "the first access-token size event the product has ever recorded"
    );
    assert_eq!(
        event.reason.as_deref(),
        Some("budget_overflow_count"),
        "reason round-trips as the stable wire string"
    );
    assert_eq!(
        TokenSizeReason::from_wire(event.reason.as_deref().expect("a reason")),
        Some(TokenSizeReason::BudgetOverflowCount),
        "and parses back to the same variant"
    );
    assert_eq!(
        event.audience.as_deref(),
        Some("https://api.example.com/orders"),
        "audience round-trips"
    );
    assert_eq!(
        event.organization_id.as_deref(),
        Some("org_budget"),
        "organization_id round-trips and is not crossed with the audience"
    );
    assert_eq!(
        event.permission_count,
        Some(412),
        "permission_count round-trips and is not the byte size"
    );
    assert_eq!(
        event.permission_status.as_deref(),
        Some("pdp_required"),
        "the permissions_status the TOKEN put on the wire round-trips, and is not crossed \
         with the reason (which is the OTHER closed vocabulary on this row)"
    );
    assert_eq!(event.byte_size, 9001, "the byte size is the token size");
    assert_eq!(
        event.claim_count, None,
        "a budget event records no claim count"
    );
}

#[tokio::test]
async fn a_recorded_budget_event_is_retention_pruned() {
    // The HONESTY claim the recorder's doc comment makes, measured rather than asserted: a
    // permission-budget row is retention pruned, so it is an operator's CONVENIENCE view of
    // a withholding and never its record of record. The other half of the same bound is the
    // read clamp, `TokenSizeEventsRepo::MAX_QUERY_LIMIT`.
    //
    // Read this test the right way round. It measures DATA LOSS on a row that records a
    // withheld permission claim, and that is acceptable ONLY because the token itself
    // carries `permissions_status`, making the wire contract the
    // durable record. If this row were the sole record, this test would be describing a bug
    // that defeats issue #98's covenant rather than a documented bound.
    let db = TestDatabase::start().await;
    // A manual clock, so the retention window is crossed deterministically rather than by
    // waiting on wall time.
    let (env, clock) = Env::deterministic(UNIX_EPOCH, 0x98);
    let scope = db.seed_scope(&env).await;
    let events = db.store().scoped(scope).token_size_events();

    let budget = |permission_count: i64| NewTokenSizeEvent {
        token_type: TokenSizeKind::AccessToken,
        byte_size: 9001,
        claim_count: None,
        client_id: "cli_budget",
        reason: Some(TokenSizeReason::BudgetOverflowBytes),
        audience: Some("https://api.example.com/orders"),
        organization_id: Some("org_budget"),
        permission_count: Some(permission_count),
        permission_status: Some("budget_exceeded"),
    };

    // A one second retention window, so the row expires one second after it is written.
    events
        .record(&env, 1_000_000, budget(412))
        .await
        .expect("record the first budget event");
    assert_eq!(
        events.recent(50).await.expect("read recent").len(),
        1,
        "the budget event is readable before its retention window closes"
    );

    // Cross the window and record a SECOND event: the prune runs on insert, so the write
    // path is what reclaims the expired row (there is no background job to wait for).
    clock.advance(Duration::from_secs(2));
    events
        .record(&env, 1_000_000, budget(7))
        .await
        .expect("record the second budget event");

    let recent = events.recent(50).await.expect("read recent");
    assert_eq!(
        recent.len(),
        1,
        "the first budget event was pruned by retention, so this sink cannot be the durable \
         record of a withholding"
    );
    assert_eq!(
        recent[0].permission_count,
        Some(7),
        "the surviving row is the second one, so the prune removed the EXPIRED row rather \
         than the newest"
    );
    // ATTRIBUTION CAVEAT, stated rather than left implicit. This test measures the
    // repository call with a LITERAL window, so on its own it cannot tell a working
    // retention thread from a store that ignores its argument and prunes on some default:
    // the sibling `token_size_events_round_trip` in this file is what shows a long window
    // keeps its rows. The threading of `diagnostics.retention_secs` through the RECORDER
    // is a different claim again, and it is measured in
    // `ironauth_oidc::policy_trace::exemption_tests::the_recorder_threads_the_configured_retention`.
}

#[tokio::test]
async fn the_per_kind_read_gives_each_event_family_its_own_clamped_window() {
    // Issue #98: the two warning families share one table, and the M9 read gives each its
    // OWN clamped window. A single shared `recent(MAX_QUERY_LIMIT)` makes the clamp a
    // STARVATION seam: enough access-token budget rows push every id_token row out of the
    // window, and the issue #91 warning family disappears from a shipped response.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let events = db.store().scoped(scope).token_size_events();

    // ONE quiet ID-token bloat row first, so every later row is newer than it.
    events
        .record(
            &env,
            TRACE_RETENTION_MICROS,
            NewTokenSizeEvent {
                token_type: TokenSizeKind::IdToken,
                byte_size: 4096,
                claim_count: Some(37),
                client_id: "cli_quiet",
                reason: None,
                audience: None,
                organization_id: None,
                permission_count: None,
                permission_status: None,
            },
        )
        .await
        .expect("record the quiet bloat event");

    // Then a flood of budget rows, comfortably past the clamp.
    let flood = TokenSizeEventsRepo::MAX_QUERY_LIMIT + 20;
    for index in 0..flood {
        events
            .record(
                &env,
                TRACE_RETENTION_MICROS,
                NewTokenSizeEvent {
                    token_type: TokenSizeKind::AccessToken,
                    byte_size: 9001,
                    claim_count: None,
                    client_id: "cli_noisy",
                    reason: Some(TokenSizeReason::BudgetOverflowBytes),
                    audience: Some("https://api.example.com/orders"),
                    organization_id: Some("org_noisy"),
                    permission_count: Some(index),
                    permission_status: Some("budget_exceeded"),
                },
            )
            .await
            .expect("record a budget event");
    }

    // The SHARED window is the failure this read avoids: it is all budget rows.
    let mixed = events
        .recent(TokenSizeEventsRepo::MAX_QUERY_LIMIT)
        .await
        .expect("read the mixed window");
    assert!(
        mixed.iter().all(|event| event.token_type == "access_token"),
        "the shared window is entirely evicted by the noisy family, which is exactly why \
         the M9 read no longer uses it for either family"
    );

    // The PER KIND windows: the quiet family survives, and the noisy one is still clamped.
    let bloat = events
        .recent_by_kind(TokenSizeKind::IdToken, TokenSizeEventsRepo::MAX_QUERY_LIMIT)
        .await
        .expect("read the id_token window");
    assert_eq!(
        bloat.len(),
        1,
        "the quiet ID-token row survives a flood of the other family"
    );
    assert_eq!(bloat[0].client_id, "cli_quiet");

    let budget = events
        .recent_by_kind(
            TokenSizeKind::AccessToken,
            TokenSizeEventsRepo::MAX_QUERY_LIMIT,
        )
        .await
        .expect("read the access_token window");
    assert_eq!(
        i64::try_from(budget.len()).expect("a window fits an i64"),
        TokenSizeEventsRepo::MAX_QUERY_LIMIT,
        "the budget window is still clamped, which is why the read renders a full window \
         as a lower bound rather than as a count"
    );
    assert!(
        budget
            .iter()
            .all(|event| event.token_type == "access_token"),
        "and it holds only its own family"
    );
}

/// The per-client scope allowlist (issue #98, migration 0096) round-trips through its
/// three states, written by the CONTROL plane and read by the DATA plane.
///
/// The two planes matter here and are exercised rather than assumed: 0096 grants the
/// column-scoped `UPDATE` to `ironauth_control` alone (unlike the twin
/// `allowed_resources`, whose 0019 grant went to the data plane), so the write must go
/// through the management door and the mint's read must still see it.
#[tokio::test]
async fn the_client_scope_allowlist_round_trips_null_empty_and_members() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let id = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .create(&env, "acme worker")
        .await
        .expect("create");

    // A freshly created client has NO allowlist: the column is NULL, which is the
    // state every client registered before 0096 is in.
    let policy = db
        .store()
        .scoped(scope)
        .client_scope_policies()
        .get(&id)
        .await
        .expect("read the fresh policy");
    assert_eq!(
        policy.allowed_scopes, None,
        "a client with no allowlist configured reads None, not Some(vec![])"
    );

    let setter = db
        .control_store()
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .client_scope_policies(scope);

    // A populated allowlist round-trips, order preserved.
    setter
        .set(
            &env,
            &id,
            Some(&["read:orders".to_owned(), "write:orders".to_owned()]),
        )
        .await
        .expect("set the allowlist");
    let policy = db
        .store()
        .scoped(scope)
        .client_scope_policies()
        .get(&id)
        .await
        .expect("read the set policy");
    assert_eq!(
        policy.allowed_scopes,
        Some(vec!["read:orders".to_owned(), "write:orders".to_owned()])
    );

    // The EMPTY allowlist is a real, distinct value stored as `[]`, never collapsed
    // into the NULL clear: it means "this client may request no scope at all".
    setter.set(&env, &id, Some(&[])).await.expect("set empty");
    let policy = db
        .store()
        .scoped(scope)
        .client_scope_policies()
        .get(&id)
        .await
        .expect("read the empty policy");
    assert_eq!(
        policy.allowed_scopes,
        Some(Vec::new()),
        "Some(empty) must NOT read back as None: they mean opposite things"
    );

    // Clearing writes NULL back, returning the client to "no allowlist".
    setter.set(&env, &id, None).await.expect("clear");
    let policy = db
        .store()
        .scoped(scope)
        .client_scope_policies()
        .get(&id)
        .await
        .expect("read the cleared policy");
    assert_eq!(policy.allowed_scopes, None);

    // Every one of those three writes (two sets and the clear) is audited under one
    // stable action.
    let rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE action = 'client.allowed_scopes.set'",
    )
    .fetch_one(db.owner_pool())
    .await
    .expect("count audit rows");
    assert_eq!(
        rows, 3,
        "each of the two sets and the clear writes exactly one audit row"
    );
}

/// A MALFORMED stored allowlist reads as the EMPTY allowlist (deny everything), never
/// as the unrestricted `None`.
///
/// This is the fail-safe direction and it is the one line of this feature a reviewer
/// should check. `ClientScopePolicyRepo::get` parses with
/// `serde_json::from_str::<Vec<String>>(..).unwrap_or_default()`, and
/// `unwrap_or_default()` on a `Vec` is the empty vector, so an unparsable value costs
/// the client every SCOPED machine token and costs nobody any authority. A request
/// carrying no `scope` still mints, since `scope` is optional, so the loss is every
/// scope the client can ask for rather than its ability to obtain a token. Flipping that
/// fallback to `None` (the unrestricted reading) makes every case below fail, which
/// was measured rather than assumed.
///
/// The values are written through the OWNER pool as raw `jsonb`, because no setter can
/// produce them: `ActingClientScopePolicyRepo::set` serializes a `&[String]` and can
/// only ever write a well-formed array. They stand in for a hand-edited row, a
/// restore from an older or newer format, and storage corruption.
///
/// The column is `jsonb`, so Postgres refuses a value that is not JSON at all and the
/// crudest malformation cannot be planted here. That does not make the parse
/// redundant, which is exactly what the corpus below shows: every one of these is
/// valid `jsonb` and none is an array of strings.
#[tokio::test]
async fn a_malformed_allowlist_denies_everything() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let id = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .create(&env, "acme worker")
        .await
        .expect("create");

    for malformed in [
        // A JSON object where an array belongs (a plausible future format change).
        r#"{"scopes": ["read:orders"]}"#,
        // An array of the WRONG element type.
        "[1, 2, 3]",
        // A nested array.
        r#"[["read:orders"]]"#,
        // A bare string, which is what a naive writer might store.
        r#""read:orders""#,
        // A scalar and a JSON null, both valid jsonb.
        "42",
        "true",
        "null",
    ] {
        sqlx::query("UPDATE clients SET allowed_scopes = $1::jsonb WHERE id = $2")
            .bind(malformed)
            .bind(id.to_string())
            .execute(db.owner_pool())
            .await
            .expect("plant the malformed value");

        let policy = db
            .store()
            .scoped(scope)
            .client_scope_policies()
            .get(&id)
            .await
            .expect("a malformed value must still READ, not error");
        assert_eq!(
            policy.allowed_scopes,
            Some(Vec::new()),
            "the malformed value `{malformed}` must read as the EMPTY allowlist \
             (deny everything), never as None (unrestricted)"
        );
        assert!(
            policy.allowed_scopes.is_some(),
            "reading `{malformed}` as None would make a corrupted row an UNRESTRICTED \
             client, which is the failure direction this whole column exists to avoid"
        );
    }
}

/// A write addressed to a client of ANOTHER scope, and one addressed to a well-formed
/// id of the caller's own scope that names no row, are both the uniform not-found and
/// audit nothing.
///
/// The second half is what pins the write path's last line of defence: with the scope
/// predicates gone, forced row-level security makes the statement match zero rows and
/// report SUCCESS, so the `rows_affected() == 0` check is the only thing that turns
/// that into a denial.
#[tokio::test]
async fn an_allowlist_write_matching_no_row_is_not_found_and_audits_nothing() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;

    // A real client of scope B, addressed from scope A.
    let victim = db
        .store()
        .scoped(scope_b)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .create(&env, "victim")
        .await
        .expect("create the victim");
    let setter = db
        .control_store()
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .client_scope_policies(scope_a);
    assert!(matches!(
        setter
            .set(&env, &victim, Some(&["read:orders".to_owned()]))
            .await,
        Err(StoreError::NotFound)
    ));

    // A well-formed id OF SCOPE A that names no row: the guard passes, the statement
    // runs, and only the rows_affected check can refuse it.
    let absent = ClientId::generate(&env, &scope_a);
    assert!(matches!(
        setter
            .set(&env, &absent, Some(&["read:orders".to_owned()]))
            .await,
        Err(StoreError::NotFound)
    ));

    // The victim's allowlist is untouched, and neither refusal wrote an audit row.
    let policy = db
        .store()
        .scoped(scope_b)
        .client_scope_policies()
        .get(&victim)
        .await
        .expect("the victim survives in its own scope");
    assert_eq!(policy.allowed_scopes, None);
    let rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE action = 'client.allowed_scopes.set'",
    )
    .fetch_one(db.owner_pool())
    .await
    .expect("count audit rows");
    assert_eq!(rows, 0, "a refused write audits nothing");
}

/// THE GRANT IS LOAD BEARING, NOT DECORATION (issue #98, migration 0096).
///
/// Every `UPDATE` grant `clients` carries for the control role is COLUMN-scoped
/// (0018's `quarantined`/`verified_at`, 0076's `first_party`), and a column-scoped
/// grant ENUMERATES columns, so a column added later is invisible to all of them.
/// Without 0096's `GRANT UPDATE (allowed_scopes) ON clients TO ironauth_control` the
/// management setter is refused by Postgres.
///
/// Demonstrated rather than asserted: revoke exactly that one grant, show the READ
/// still works (0018's table-wide `SELECT` is unaffected), show the write fail with
/// SQLSTATE 42501 and the column unchanged, restore the grant, and show the identical
/// call succeed. Without the restore half the test would pass against a setter that
/// was broken for some entirely other reason, and a MISSPELLED column name in the
/// migration would surface as 42703 rather than 42501.
#[tokio::test]
async fn the_control_column_grant_is_load_bearing_for_allowed_scopes() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let id = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .create(&env, "acme worker")
        .await
        .expect("create");

    // The owner pool is the schema owner, so this leaves the database in exactly the
    // state an operator who applied 0018 and 0076 and skipped 0096 would have.
    sqlx::query("REVOKE UPDATE (allowed_scopes) ON clients FROM ironauth_control")
        .execute(db.owner_pool())
        .await
        .expect("revoke the 0096 column grant");

    let setter = db
        .control_store()
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .client_scope_policies(scope);
    let error = setter
        .set(&env, &id, Some(&["read:orders".to_owned()]))
        .await
        .expect_err("the setter must be refused without the column grant");
    let sqlstate = match &error {
        StoreError::Database(sqlx::Error::Database(database)) => database
            .code()
            .map(std::borrow::Cow::into_owned)
            .expect("the refusal carries a SQLSTATE"),
        other => panic!("expected a database error, got {other:?}"),
    };
    assert_eq!(
        sqlstate, "42501",
        "the missing column grant must surface as insufficient_privilege"
    );

    // The READ is unaffected: 0018 granted the control role a TABLE-wide SELECT, which
    // covers a column added later, and 0096 narrowed only UPDATE.
    let policy = db
        .control_store()
        .management()
        .client_scope_policies(scope)
        .get(&id)
        .await
        .expect("the control-plane read needs no new grant");
    assert_eq!(
        policy.allowed_scopes, None,
        "the refused write left the column untouched"
    );

    // RESTORE the grant, and the SAME call now succeeds.
    sqlx::query("GRANT UPDATE (allowed_scopes) ON clients TO ironauth_control")
        .execute(db.owner_pool())
        .await
        .expect("restore the 0096 column grant");
    db.control_store()
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .client_scope_policies(scope)
        .set(&env, &id, Some(&["read:orders".to_owned()]))
        .await
        .expect("with the grant restored the same call succeeds");
    let policy = db
        .store()
        .scoped(scope)
        .client_scope_policies()
        .get(&id)
        .await
        .expect("read back");
    assert_eq!(policy.allowed_scopes, Some(vec!["read:orders".to_owned()]));

    // And the refused write audited nothing: the audit row and the data change share
    // one transaction, so a refusal rolls both back.
    let rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE action = 'client.allowed_scopes.set'",
    )
    .fetch_one(db.owner_pool())
    .await
    .expect("count audit rows");
    assert_eq!(rows, 1, "only the successful write is audited");
}
