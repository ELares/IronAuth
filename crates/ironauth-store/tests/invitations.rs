// SPDX-License-Identifier: MIT OR Apache-2.0

//! User invitations (issue #60), over a real database (`DATABASE_URL`).
//!
//! Pins the acceptance criteria at the persistence layer: the single-use token is
//! stored only as its digest (a database dump yields nothing replayable); accepting
//! ATOMICALLY consumes the invitation and activates the invited user
//! (`pending_verification` -> active) with a credential set, so a second accept and a
//! CONCURRENT double-accept storm redeem AT MOST ONCE (never two activations); a
//! stale invite is refused against the clock; a revoked invitation is unacceptable;
//! the invited identifier is envelope-encrypted (no plaintext dump) and never leaks
//! across tenants; a token minted in one tenant never resolves in another; every
//! lifecycle mutation is audited; and the create is ATOMIC, so a failure at any of the
//! three seams inside it leaves no user, no invitation, no audit row and no stored
//! Idempotency-Key, and the same key then creates cleanly (issue #247).

use std::time::{Duration, SystemTime};

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, InvitationCreateFailurePoint, InvitationCredentialType, InvitationId,
    InvitationState, MintedInvitationToken, NewAdminUser, NewInvitedUser, Scope, StoreError,
    UserId, UserState, invitation_token_digest, mint_invitation_token, mint_invitation_token_for,
};
use sqlx::Row;

/// A valid Argon2id PHC verifier (a fixed one; hashing is exercised in the oidc/admin
/// layers, the store only persists the string).
const PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaGhhc2hoYXNo";
/// The store's unusable-password sentinel: a credential-less (passkey) user carries
/// it until a factor is enrolled.
const UNUSABLE: &str = "!";

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

/// Create a `pending_verification` user and an invitation for it in `scope`, returning
/// the invitation id, the user id, and the raw one-time token.
async fn create_invitation(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    identifier: &str,
    credential_type: InvitationCredentialType,
    ttl_micros: i64,
) -> (InvitationId, UserId, String) {
    let created = now_micros(env);
    let MintedInvitationToken { token, digest, id } = mint_invitation_token(env, &scope);
    // The joined create is a CONTROL-plane (admin) operation: the migration grants
    // INSERT on users and user_invitations to the control role only, exactly as the
    // admin API uses the control-plane store. This is the SAME call the management
    // surface makes, so every fixture below exercises the production path.
    let user_id = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .invitations()
        .create_with_user(
            env,
            NewInvitedUser {
                user: NewAdminUser {
                    id: None,
                    identifier,
                    password_hash: None,
                    claims_json: None,
                    external_id: None,
                    state: UserState::PendingVerification,
                    foreign_password_hash: None,
                    foreign_password_algo: None,
                    traits: None,
                },
                invitation_id: &id,
                token_digest: &digest,
                credential_type,
                org_context: None,
                expires_at_unix_micros: created.saturating_add(ttl_micros),
            },
            created,
            None,
        )
        .await
        .expect("create the invited user and invitation");
    (id, user_id, token)
}

/// Accept a presented token in `scope`, setting `password_hash` (a password
/// invitation) or `None` (a passkey), against the current clock.
async fn accept(
    store: &ironauth_store::Store,
    env: &Env,
    scope: Scope,
    token: &str,
    password_hash: Option<&str>,
) -> Result<UserId, StoreError> {
    let now = now_micros(env);
    store
        .scoped(scope)
        .acting(store_test_actor(env), CorrelationId::generate(env))
        .invitations()
        .accept(env, token, password_hash, now)
        .await
        .map(|accepted| accepted.user_id)
}

/// A well-known service actor for the accept path (the invitee side has no admin
/// actor; a fixed service id keeps the audit envelope stable).
fn store_test_actor(env: &Env) -> ironauth_store::ActorRef {
    let _ = env;
    ironauth_store::ActorRef::service(ironauth_store::ServiceId::from_seed_bytes([7_u8; 16]))
}

/// The user's current lifecycle state.
async fn user_state(db: &TestDatabase, scope: Scope, id: &UserId) -> UserState {
    db.store()
        .scoped(scope)
        .users()
        .get(id)
        .await
        .expect("user get")
        .state
}

/// The user's stored password hash (the sentinel when none was ever set).
async fn user_password_hash(db: &TestDatabase, scope: Scope, id: &UserId) -> String {
    db.store()
        .scoped(scope)
        .users()
        .password_hash_for_subject(id)
        .await
        .expect("hash read")
        .expect("hash present")
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test]
async fn accept_activates_the_user_sets_the_credential_and_is_single_use() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x60);
    let scope = db.seed_scope(&env).await;
    let (_id, user_id, token) = create_invitation(
        &db,
        &env,
        scope,
        "ada@example.test",
        InvitationCredentialType::Password,
        1_000_000_000,
    )
    .await;

    // Before accept the user is pending_verification and has no usable credential.
    assert_eq!(
        user_state(&db, scope, &user_id).await,
        UserState::PendingVerification
    );
    assert_eq!(user_password_hash(&db, scope, &user_id).await, UNUSABLE);

    // Accepting activates the user and sets the credential.
    let accepted = accept(db.store(), &env, scope, &token, Some(PASSWORD_HASH))
        .await
        .expect("first accept succeeds");
    assert_eq!(accepted, user_id, "accept returns the activated user");
    assert_eq!(user_state(&db, scope, &user_id).await, UserState::Active);
    assert_eq!(
        user_password_hash(&db, scope, &user_id).await,
        PASSWORD_HASH,
        "the accept set the credential"
    );

    // A SECOND accept of the same token fails: the invitation was consumed.
    let second = accept(db.store(), &env, scope, &token, Some(PASSWORD_HASH)).await;
    assert!(
        matches!(second, Err(StoreError::NotFound)),
        "a redeemed token is the uniform not-found, got {second:?}"
    );
}

#[tokio::test]
async fn a_passkey_invitation_activates_without_provisioning_a_password() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x61);
    let scope = db.seed_scope(&env).await;
    let (_id, user_id, token) = create_invitation(
        &db,
        &env,
        scope,
        "grace@example.test",
        InvitationCredentialType::Passkey,
        1_000_000_000,
    )
    .await;

    // A passkey invitation carries no password; the accept must not require one and
    // must not provision one.
    accept(db.store(), &env, scope, &token, None)
        .await
        .expect("passkey accept succeeds without a password");
    assert_eq!(user_state(&db, scope, &user_id).await, UserState::Active);
    assert_eq!(
        user_password_hash(&db, scope, &user_id).await,
        UNUSABLE,
        "no password was ever provisioned for a passkey invitation"
    );
}

#[tokio::test]
async fn a_concurrent_double_accept_storm_redeems_at_most_once() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x62);
    let scope = db.seed_scope(&env).await;
    let (_id, user_id, token) = create_invitation(
        &db,
        &env,
        scope,
        "race@example.test",
        InvitationCredentialType::Password,
        1_000_000_000,
    )
    .await;

    // Fire many parallel accepts of the SAME token against the SAME database.
    let mut handles = Vec::new();
    for _ in 0..12 {
        let store = db.store().clone();
        let env = env.clone();
        let token = token.clone();
        handles.push(tokio::spawn(async move {
            accept(&store, &env, scope, &token, Some(PASSWORD_HASH)).await
        }));
    }
    let mut successes = 0_u32;
    for handle in handles {
        if handle.await.expect("task joins").is_ok() {
            successes += 1;
        }
    }
    assert_eq!(
        successes, 1,
        "exactly one accept wins the race; the rest lose"
    );
    // The user was activated exactly once (a single active row, no double provision).
    assert_eq!(user_state(&db, scope, &user_id).await, UserState::Active);
}

#[tokio::test]
async fn an_expired_invitation_is_refused_against_the_clock() {
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x63);
    let scope = db.seed_scope(&env).await;
    // A short 100-second TTL.
    let (_id, user_id, token) = create_invitation(
        &db,
        &env,
        scope,
        "stale@example.test",
        InvitationCredentialType::Password,
        100_000_000,
    )
    .await;

    // Advance the clock past the expiry.
    clock.advance(Duration::from_secs(200));

    // The stale token resolves to nothing and the accept refuses it.
    let resolved = db
        .store()
        .scoped(scope)
        .invitations()
        .resolve_pending(&token, now_micros(&env))
        .await
        .expect("resolve");
    assert!(resolved.is_none(), "a stale invitation does not resolve");
    let accepted = accept(db.store(), &env, scope, &token, Some(PASSWORD_HASH)).await;
    assert!(
        matches!(accepted, Err(StoreError::NotFound)),
        "an expired token is the uniform not-found, got {accepted:?}"
    );
    assert_eq!(
        user_state(&db, scope, &user_id).await,
        UserState::PendingVerification,
        "an expired accept never activates the user"
    );
}

#[tokio::test]
async fn a_revoked_invitation_is_unacceptable() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x64);
    let scope = db.seed_scope(&env).await;
    let (id, user_id, token) = create_invitation(
        &db,
        &env,
        scope,
        "revoked@example.test",
        InvitationCredentialType::Password,
        1_000_000_000,
    )
    .await;

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .invitations()
        .revoke(&env, &id, None)
        .await
        .expect("revoke");

    // A revoked invitation resolves to nothing and cannot be accepted.
    let resolved = db
        .store()
        .scoped(scope)
        .invitations()
        .resolve_pending(&token, now_micros(&env))
        .await
        .expect("resolve");
    assert!(resolved.is_none(), "a revoked invitation does not resolve");
    let accepted = accept(db.store(), &env, scope, &token, Some(PASSWORD_HASH)).await;
    assert!(
        matches!(accepted, Err(StoreError::NotFound)),
        "a revoked token is the uniform not-found, got {accepted:?}"
    );
    assert_eq!(
        user_state(&db, scope, &user_id).await,
        UserState::PendingVerification
    );

    // A repeat revoke matches no pending row: the uniform not-found.
    let repeat = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .invitations()
        .revoke(&env, &id, None)
        .await;
    assert!(
        matches!(repeat, Err(StoreError::NotFound)),
        "a repeat revoke of an already-revoked invitation is the uniform not-found, got {repeat:?}"
    );
}

#[tokio::test]
async fn resend_rotates_the_token_invalidating_the_prior_one() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x65);
    let scope = db.seed_scope(&env).await;
    let (id, _user_id, first_token) = create_invitation(
        &db,
        &env,
        scope,
        "resend@example.test",
        InvitationCredentialType::Password,
        1_000_000_000,
    )
    .await;

    // Resend: mint a fresh token for the SAME invitation and overwrite the digest.
    let MintedInvitationToken {
        token: second_token,
        digest: second_digest,
        ..
    } = mint_invitation_token_for(&env, id);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .invitations()
        .resend(
            &env,
            &id,
            &second_digest,
            now_micros(&env).saturating_add(1_000_000_000),
            None,
        )
        .await
        .expect("resend");

    // The prior token is now dead; the fresh token accepts.
    let prior = accept(db.store(), &env, scope, &first_token, Some(PASSWORD_HASH)).await;
    assert!(
        matches!(prior, Err(StoreError::NotFound)),
        "the prior token is invalidated by the resend, got {prior:?}"
    );
    accept(db.store(), &env, scope, &second_token, Some(PASSWORD_HASH))
        .await
        .expect("the fresh token accepts");
}

#[tokio::test]
async fn only_the_token_digest_is_stored_never_the_raw_token() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x66);
    let scope = db.seed_scope(&env).await;
    let (id, _user_id, token) = create_invitation(
        &db,
        &env,
        scope,
        "digest@example.test",
        InvitationCredentialType::Password,
        1_000_000_000,
    )
    .await;

    // The "database dump" a stolen backup would expose (read as the owner, bypassing
    // row-level security).
    let row = sqlx::query(
        "SELECT token_digest, target_identifier_sealed, target_identifier_bidx \
         FROM user_invitations WHERE id = $1",
    )
    .bind(id.to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("dump invitation row");
    let stored_digest: String = row.get("token_digest");

    // The stored digest is the SHA-256 of the whole token, and the raw token (and its
    // secret half) appear nowhere in the row.
    assert_eq!(
        stored_digest,
        invitation_token_digest(&token),
        "the stored value is exactly the digest of the whole token"
    );
    assert_ne!(stored_digest, token, "the raw token is not stored");
    let token_bytes = token.as_bytes();
    let secret = token.rsplit('~').next().expect("token has a secret half");
    assert!(!contains(stored_digest.as_bytes(), token_bytes));
    let sealed: Vec<u8> = row.get("target_identifier_sealed");
    let bidx: Vec<u8> = row.get("target_identifier_bidx");
    assert!(
        !contains(&sealed, secret.as_bytes()) && !contains(&bidx, secret.as_bytes()),
        "the token secret leaks into no other column"
    );
}

#[tokio::test]
async fn the_invited_identifier_is_envelope_encrypted_at_rest() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x67);
    let scope = db.seed_scope(&env).await;
    let identifier = "secret-person@example.test";
    let (id, _user_id, _token) = create_invitation(
        &db,
        &env,
        scope,
        identifier,
        InvitationCredentialType::Password,
        1_000_000_000,
    )
    .await;

    // A dump reveals neither the plaintext identifier nor a plaintext column for it.
    let row = sqlx::query(
        "SELECT target_identifier_sealed, target_identifier_bidx FROM user_invitations \
         WHERE id = $1",
    )
    .bind(id.to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("dump invitation row");
    let sealed: Vec<u8> = row.get("target_identifier_sealed");
    let bidx: Vec<u8> = row.get("target_identifier_bidx");
    assert!(
        !contains(&sealed, identifier.as_bytes()),
        "the sealed identifier is not the plaintext"
    );
    assert!(
        !contains(&bidx, identifier.as_bytes()),
        "the blind index is not the plaintext"
    );

    // The management read still recovers the plaintext (it opens the sealed value).
    let record = db
        .store()
        .scoped(scope)
        .invitations()
        .get(&id)
        .await
        .expect("get invitation");
    assert_eq!(record.target_identifier, identifier);
}

#[tokio::test]
async fn a_token_and_an_invitation_never_cross_tenants() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x68);
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let (id_a, user_a, token_a) = create_invitation(
        &db,
        &env,
        scope_a,
        "tenant-a@example.test",
        InvitationCredentialType::Password,
        1_000_000_000,
    )
    .await;

    // A token minted in tenant A resolves to nothing under tenant B's scope.
    let resolved_in_b = db
        .store()
        .scoped(scope_b)
        .invitations()
        .resolve_pending(&token_a, now_micros(&env))
        .await
        .expect("resolve in b");
    assert!(
        resolved_in_b.is_none(),
        "a token from tenant A does not resolve in tenant B"
    );

    // Accepting A's token under B's scope is the uniform not-found and activates
    // nobody in either tenant.
    let accepted_in_b = accept(db.store(), &env, scope_b, &token_a, Some(PASSWORD_HASH)).await;
    assert!(
        matches!(accepted_in_b, Err(StoreError::NotFound)),
        "A's token cannot be accepted into B, got {accepted_in_b:?}"
    );
    assert_eq!(
        user_state(&db, scope_a, &user_a).await,
        UserState::PendingVerification,
        "A's user is untouched by the cross-tenant attempt"
    );

    // A's invitation id parsed under B's scope is the uniform not-found.
    let get_in_b = db.store().scoped(scope_b).invitations().get(&id_a).await;
    assert!(matches!(get_in_b, Err(StoreError::NotFound)));
}

#[tokio::test]
async fn create_redeem_and_revoke_are_each_audited() {
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x69);
    let scope = db.seed_scope(&env).await;

    // Create + redeem one invitation, and create + revoke another, then read the
    // scope's audit log.
    let (_id1, _user1, token1) = create_invitation(
        &db,
        &env,
        scope,
        "audit-one@example.test",
        InvitationCredentialType::Password,
        1_000_000_000,
    )
    .await;
    clock.advance(Duration::from_secs(1));
    accept(db.store(), &env, scope, &token1, Some(PASSWORD_HASH))
        .await
        .expect("accept");
    let (id2, _user2, _token2) = create_invitation(
        &db,
        &env,
        scope,
        "audit-two@example.test",
        InvitationCredentialType::Password,
        1_000_000_000,
    )
    .await;
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .invitations()
        .revoke(&env, &id2, None)
        .await
        .expect("revoke");

    let actions: Vec<String> = db
        .store()
        .scoped(scope)
        .audit()
        .list()
        .await
        .expect("audit list")
        .into_iter()
        .map(|row| row.action)
        .collect();
    for expected in [
        "invitation.create",
        "invitation.redeem",
        "invitation.revoke",
    ] {
        assert!(
            actions.iter().any(|a| a == expected),
            "the audit log records {expected}; saw {actions:?}"
        );
    }
}

/// The `NewInvitedUser` spec the joined create takes for one invited identity.
fn invited_user<'a>(
    identifier: &'a str,
    user_id: &'a UserId,
    invitation_id: &'a InvitationId,
    digest: &'a str,
    expires_at_unix_micros: i64,
) -> NewInvitedUser<'a> {
    NewInvitedUser {
        user: NewAdminUser {
            id: Some(user_id),
            identifier,
            password_hash: None,
            claims_json: None,
            external_id: None,
            state: UserState::PendingVerification,
            foreign_password_hash: None,
            foreign_password_algo: None,
            traits: None,
        },
        invitation_id,
        token_digest: digest,
        credential_type: InvitationCredentialType::Password,
        org_context: None,
        expires_at_unix_micros,
    }
}

/// How many rows of `table` exist in `scope`, read as the OWNER (bypassing row-level
/// security), so a row hidden from a role still counts.
async fn count_in_scope(db: &TestDatabase, scope: Scope, table: &str) -> i64 {
    // `table` is one of two literals chosen by this test file, never caller input.
    let sql =
        format!("SELECT COUNT(*) AS n FROM {table} WHERE tenant_id = $1 AND environment_id = $2");
    sqlx::query(&sql)
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .fetch_one(db.owner_pool())
        .await
        .expect("count rows")
        .get::<i64, _>("n")
}

/// The audit actions recorded in `scope`, in the order the log holds them.
async fn audit_actions(db: &TestDatabase, scope: Scope) -> Vec<String> {
    db.store()
        .scoped(scope)
        .audit()
        .list()
        .await
        .expect("audit list")
        .into_iter()
        .map(|row| row.action)
        .collect()
}

/// How many `idempotency_keys` rows carry `key`, read as the owner.
async fn idempotency_rows(db: &TestDatabase, key: &str) -> i64 {
    sqlx::query("SELECT COUNT(*) AS n FROM idempotency_keys WHERE idempotency_key = $1")
        .bind(key)
        .fetch_one(db.owner_pool())
        .await
        .expect("count idempotency rows")
        .get::<i64, _>("n")
}

// One linear failure-then-retry narrative: injecting the failure, asserting the four
// post-conditions, retrying, and asserting the five the commit owes. Splitting it would
// hide which assertions belong to which half.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn a_failed_invitation_create_leaves_nothing_and_the_same_key_then_succeeds() {
    // THE DECISIVE TEST for issue #247. The create used to run the #52 audited user
    // create in one transaction and the invitation (which also committed the
    // Idempotency-Key record) in a SECOND. A failure of the second after the first
    // committed left an orphaned pending_verification user with no invitation and no
    // stored key: the retry under the SAME key missed the replay store, re-ran the user
    // create, hit the identifier unique violation and answered a CONFLICT, and the
    // identifier stayed wedged behind the ghost until an operator deleted it.
    //
    // The failure is injected at exactly that instant, through the testing-only probe,
    // and the two halves of the claim are asserted: NOTHING survives the failure, and
    // the SAME key with the SAME identifier then creates cleanly.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0xA1);
    let scope = db.seed_scope(&env).await;
    let identifier = "wedged@example.test";
    let key = "inv-atomic-key";
    let created = now_micros(&env);

    let users_before = count_in_scope(&db, scope, "users").await;

    // The failing attempts, one at EACH of the three seams a split create could be
    // reintroduced at. Injecting only after the user (the old split) leaves the other end
    // unmeasured: MEASURED, a mutation that committed everything staged so far and
    // finished in a SECOND transaction survived a suite that probed only that one point.
    for at in [
        InvitationCreateFailurePoint::AfterIdempotency,
        InvitationCreateFailurePoint::AfterUser,
        InvitationCreateFailurePoint::BeforeCommit,
    ] {
        let MintedInvitationToken { digest, id, .. } = mint_invitation_token(&env, &scope);
        let user_id = UserId::generate(&env, &scope);
        let failed = db
            .control_store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .invitations()
            .create_with_user_injecting_failure(
                &env,
                invited_user(identifier, &user_id, &id, &digest, created + 1_000_000_000),
                created,
                Some(ironauth_store::IdempotencyWrite {
                    credential_ref: "cred-247",
                    key,
                    request_fingerprint: "fp-247",
                    response_status: 201,
                    response_body: "{}",
                }),
                at,
            )
            .await;
        assert!(
            failed.is_err(),
            "the failure injected at {at:?} must fail: {failed:?}"
        );

        // NOTHING survives it: no ghost user, no invitation, neither audit row, and no
        // idempotency record the replay store would have to honor.
        assert_eq!(
            count_in_scope(&db, scope, "users").await,
            users_before,
            "a create rolled back at {at:?} leaves no ghost pending_verification user"
        );
        assert_eq!(
            count_in_scope(&db, scope, "user_invitations").await,
            0,
            "a create rolled back at {at:?} leaves no invitation"
        );
        // Neither audit row survives. The scope's audit log is NOT empty (provisioning
        // the scope's KEK and DEK is idempotent, commits on its own, and audits itself;
        // a provisioned DEK left behind by a rolled-back create is not a partial
        // invitation, it is a scope that is ready to seal), so the assertion is over the
        // two actions this create owes rather than over a row count.
        let after_failure = audit_actions(&db, scope).await;
        for absent in ["user.create", "invitation.create"] {
            assert!(
                !after_failure.iter().any(|a| a == absent),
                "a create rolled back at {at:?} leaves no {absent} audit row; saw {after_failure:?}"
            );
        }
        assert_eq!(
            idempotency_rows(&db, key).await,
            0,
            "a create rolled back at {at:?} stores no Idempotency-Key record"
        );
    }

    // The RETRY: the SAME Idempotency-Key and the SAME identifier. Before the fix this
    // is where the wedge showed, as a conflict on an identifier no live row held.
    let MintedInvitationToken {
        digest: retry_digest,
        id: retry_id,
        ..
    } = mint_invitation_token(&env, &scope);
    let retry_user_id = UserId::generate(&env, &scope);
    let landed = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .invitations()
        .create_with_user(
            &env,
            invited_user(
                identifier,
                &retry_user_id,
                &retry_id,
                &retry_digest,
                created + 1_000_000_000,
            ),
            created,
            Some(ironauth_store::IdempotencyWrite {
                credential_ref: "cred-247",
                key,
                request_fingerprint: "fp-247",
                response_status: 201,
                response_body: "{}",
            }),
        )
        .await
        .expect("the same key and identifier retry cleanly after a failed create");
    assert_eq!(landed, retry_user_id, "the create lands on the supplied id");

    // And the retry committed the whole thing: the user, the invitation bound to it,
    // both audit rows, and the idempotency record a replay will serve.
    let record = db
        .control_store()
        .scoped(scope)
        .invitations()
        .get(&retry_id)
        .await
        .expect("the retried invitation is readable");
    assert_eq!(record.user_id, retry_user_id);
    assert_eq!(record.target_identifier, identifier);
    assert_eq!(record.state, InvitationState::Pending);
    assert_eq!(
        idempotency_rows(&db, key).await,
        1,
        "the successful retry stores the Idempotency-Key record"
    );
    let actions = audit_actions(&db, scope).await;
    for expected in ["user.create", "invitation.create"] {
        assert!(
            actions.iter().any(|a| a == expected),
            "the committed create writes {expected}; saw {actions:?}"
        );
    }
    assert_eq!(
        actions.iter().filter(|a| *a == "user.create").count(),
        1,
        "exactly ONE user.create: the rolled-back attempt contributed none"
    );
}

// Four creates in one narrative, each one the CONTRAST for the previous: the same
// identifier, then a repeated mint, then a repeated user id, then the identifier the
// repeated user id named. Splitting it would separate an assertion from the state that
// makes it mean something.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn a_taken_identifier_and_a_mint_collision_are_different_errors() {
    // The joined create folds two writes that used to report the same
    // `StoreError::Conflict` for very different reasons: the invited LOGIN HANDLE is
    // taken (a 409 the caller can act on) and one of the THREE values this path mints
    // from 256 bits collided (not a caller fault, an opaque server error). The three are
    // the `usr_` id of the account it provisions, the `inv_` handle, and the token
    // digest, and all three are asserted here, because the `usr_` id rides the SAME
    // insert as the login handle and so is the one a naive mapping folds back into the
    // 409. Conflating them would tell an operator that the identifier they chose is
    // taken when it is not.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0xA2);
    let scope = db.seed_scope(&env).await;
    let created = now_micros(&env);
    let expires = created + 1_000_000_000;

    let MintedInvitationToken { digest, id, .. } = mint_invitation_token(&env, &scope);
    let user_id = UserId::generate(&env, &scope);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .invitations()
        .create_with_user(
            &env,
            invited_user("taken@example.test", &user_id, &id, &digest, expires),
            created,
            None,
        )
        .await
        .expect("the first create lands");

    // A SECOND create for the same identifier, with a FRESH handle and digest: the
    // identifier is what collides, so it is the caller-facing conflict.
    let MintedInvitationToken {
        digest: fresh_digest,
        id: fresh_id,
        ..
    } = mint_invitation_token(&env, &scope);
    let second_user = UserId::generate(&env, &scope);
    let taken = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .invitations()
        .create_with_user(
            &env,
            invited_user(
                "taken@example.test",
                &second_user,
                &fresh_id,
                &fresh_digest,
                expires,
            ),
            created,
            None,
        )
        .await;
    assert!(
        matches!(taken, Err(StoreError::Conflict)),
        "a taken identifier is the caller-facing conflict: {taken:?}"
    );

    // A create with a FRESH identifier but the ALREADY-STORED handle and digest: the
    // mint is what collided, which the caller neither caused nor can act on.
    let third_user = UserId::generate(&env, &scope);
    let collided = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .invitations()
        .create_with_user(
            &env,
            invited_user("fresh@example.test", &third_user, &id, &digest, expires),
            created,
            None,
        )
        .await;
    assert!(
        matches!(collided, Err(StoreError::InvitationMintCollision)),
        "a handle or digest collision is its OWN error, never the identifier 409: {collided:?}"
    );

    // A create with a FRESH identifier, a FRESH handle and a FRESH digest, but the
    // ALREADY-STORED `usr_` id. This is the asymmetric case: the collision is on the
    // users PRIMARY KEY, which rides the same INSERT as the login-handle blind index, so
    // a mapping that folds every unique violation on that insert into `Conflict` answers
    // 409 about an identifier that is demonstrably free (this create's own
    // `mint-collision@example.test`, which the last assertion then uses successfully).
    let MintedInvitationToken {
        digest: id_race_digest,
        id: id_race_id,
        ..
    } = mint_invitation_token(&env, &scope);
    let duplicate_user = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .invitations()
        .create_with_user(
            &env,
            invited_user(
                "mint-collision@example.test",
                &user_id,
                &id_race_id,
                &id_race_digest,
                expires,
            ),
            created,
            None,
        )
        .await;
    assert!(
        matches!(duplicate_user, Err(StoreError::InvitationMintCollision)),
        "a collision on the MINTED user id is a mint collision, not the identifier 409: \
         {duplicate_user:?}"
    );
    let free_user = UserId::generate(&env, &scope);
    let MintedInvitationToken {
        digest: free_digest,
        id: free_id,
        ..
    } = mint_invitation_token(&env, &scope);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .invitations()
        .create_with_user(
            &env,
            invited_user(
                "mint-collision@example.test",
                &free_user,
                &free_id,
                &free_digest,
                expires,
            ),
            created,
            None,
        )
        .await
        .expect("the identifier the user-id collision named was never taken");

    // And the collided attempt left no ghost either: the fresh identifier is still free.
    let fourth_user = UserId::generate(&env, &scope);
    let MintedInvitationToken {
        digest: ok_digest,
        id: ok_id,
        ..
    } = mint_invitation_token(&env, &scope);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .invitations()
        .create_with_user(
            &env,
            invited_user(
                "fresh@example.test",
                &fourth_user,
                &ok_id,
                &ok_digest,
                expires,
            ),
            created,
            None,
        )
        .await
        .expect("the identifier a collided create named is still free");
}

#[tokio::test]
async fn the_invitation_state_wire_forms_round_trip() {
    // A database-free guard that the closed lifecycle wire strings match the
    // migration CHECK and parse back, so a value outside the set can never be stored
    // or resurrected.
    for state in [
        InvitationState::Pending,
        InvitationState::Accepted,
        InvitationState::Revoked,
    ] {
        assert_eq!(InvitationState::from_wire(state.as_str()), Some(state));
    }
    assert_eq!(InvitationState::from_wire("bogus"), None);
    for kind in [
        InvitationCredentialType::Password,
        InvitationCredentialType::Passkey,
    ] {
        assert_eq!(InvitationCredentialType::parse(kind.as_str()), Some(kind));
    }
    assert_eq!(InvitationCredentialType::parse("totp"), None);
}

/// Everything queued for the webhook fan-out in this scope.
async fn queued_events(db: &TestDatabase, scope: Scope) -> Vec<serde_json::Value> {
    use std::time::Duration;

    db.store()
        .scoped(scope)
        .outbox()
        .claim(
            &Env::system(),
            ironauth_store::WEBHOOK_EVENT_CONSUMER,
            Duration::from_secs(30),
            100,
        )
        .await
        .expect("claim webhook events")
        .into_iter()
        .map(|message| message.payload)
        .collect()
}

/// Revoking a pending invitation emits `invitation.revoked`, and a REPEAT emits nothing.
///
/// The retry half is the point. The revoke matches only a `pending` row, so a second call
/// affects nothing and returns the uniform not-found -- and the event has to inherit that
/// guard rather than fire again. A receiver counting revocations must not see two for one
/// invitation because a client retried.
#[tokio::test]
async fn revoking_an_invitation_emits_once_and_a_retry_emits_nothing() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (id, _user, _token) = create_invitation(
        &db,
        &env,
        scope,
        "revoked@example.test",
        InvitationCredentialType::Password,
        3_600_000_000,
    )
    .await;

    let envelope = ironauth_store::event_catalog::envelope(
        "evt_invitation_revoked",
        "invitation.revoked",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        1,
        &serde_json::json!({ "invitation_id": id.to_string() }),
    )
    .expect("invitation.revoked is registered");
    let subject = id.to_string();
    let domain_event = ironauth_store::DomainEvent {
        id: "evt_invitation_revoked",
        subject: &subject,
        envelope: &envelope,
    };

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .invitations()
        .revoke_with_event(&env, &id, None, Some(&domain_event))
        .await
        .expect("revoke");

    let events = queued_events(&db, scope).await;
    assert_eq!(events.len(), 1, "the revocation enqueues exactly one event");
    assert_eq!(events[0]["type"], "invitation.revoked");
    assert_eq!(events[0]["payload"]["invitation_id"], id.to_string());
    ironauth_store::event_catalog::validate_event(&events[0])
        .expect("the envelope validates against the registry the fan-out enforces");

    // THE RETRY. No pending row matches now, so the store's guard must keep it silent.
    let repeat = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .invitations()
        .revoke_with_event(&env, &id, None, Some(&domain_event))
        .await;
    assert!(
        matches!(repeat, Err(StoreError::NotFound)),
        "a repeat revoke is the uniform not-found: {repeat:?}"
    );
    assert!(
        queued_events(&db, scope).await.is_empty(),
        "a revoke that changed nothing must not announce a second revocation"
    );
}

/// A revoke carrying no event enqueues nothing.
///
/// The paired negative: without it the test above passes for a revoke that emits
/// unconditionally, which would fire for every internal path that revokes an invitation.
#[tokio::test]
async fn revoking_an_invitation_without_an_event_enqueues_nothing() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (id, _user, _token) = create_invitation(
        &db,
        &env,
        scope,
        "silent@example.test",
        InvitationCredentialType::Password,
        3_600_000_000,
    )
    .await;

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .invitations()
        .revoke(&env, &id, None)
        .await
        .expect("revoke");

    assert!(
        queued_events(&db, scope).await.is_empty(),
        "a revocation with no event must not invent one"
    );
}

/// The joined create emits `invitation.created`, naming both rows it wrote.
///
/// The user id is asserted as well as the invitation id, because the joined create makes both
/// in ONE transaction (issue #247) and an event naming only the invitation would leave a
/// consumer unable to say which pending account it belongs to.
#[tokio::test]
async fn creating_an_invitation_emits_an_event_naming_the_invitation_and_its_user() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let created = now_micros(&env);
    let MintedInvitationToken { token, digest, id } = mint_invitation_token(&env, &scope);
    let _ = token;
    // Minted here, exactly as the management handler does, so the envelope names the id the
    // create will actually write. Letting the store generate it would leave the test
    // asserting a placeholder against itself.
    let minted_user = UserId::generate(&env, &scope);

    let envelope = ironauth_store::event_catalog::envelope(
        "evt_invitation_created",
        "invitation.created",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        1,
        &serde_json::json!({
            "invitation_id": id.to_string(),
            "user_id": minted_user.to_string(),
        }),
    )
    .expect("invitation.created is registered");
    let subject = id.to_string();
    let domain_event = ironauth_store::DomainEvent {
        id: "evt_invitation_created",
        subject: &subject,
        envelope: &envelope,
    };

    let user_id = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .invitations()
        .create_with_user_with_event(
            &env,
            NewInvitedUser {
                user: NewAdminUser {
                    id: Some(&minted_user),
                    identifier: "invited@example.test",
                    password_hash: None,
                    claims_json: None,
                    external_id: None,
                    state: UserState::PendingVerification,
                    foreign_password_hash: None,
                    foreign_password_algo: None,
                    traits: None,
                },
                invitation_id: &id,
                token_digest: &digest,
                credential_type: InvitationCredentialType::Password,
                org_context: None,
                expires_at_unix_micros: created.saturating_add(3_600_000_000),
            },
            created,
            None,
            Some(&domain_event),
        )
        .await
        .expect("joined create");

    let events = queued_events(&db, scope).await;
    assert_eq!(events.len(), 1, "the create enqueues exactly one event");
    assert_eq!(events[0]["type"], "invitation.created");
    assert_eq!(events[0]["payload"]["invitation_id"], id.to_string());
    ironauth_store::event_catalog::validate_event(&events[0])
        .expect("the envelope validates against the registry the fan-out enforces");
    // The event names the user the create actually wrote, not merely SOME user.
    assert_eq!(events[0]["payload"]["user_id"], user_id.to_string());
    assert_eq!(user_id, minted_user, "the create wrote the id it was given");
}

/// A joined create carrying no event enqueues nothing.
///
/// The paired negative: without it the test above passes for a create that emits
/// unconditionally, which would fire for every internal path that mints an invitation.
#[tokio::test]
async fn creating_an_invitation_without_an_event_enqueues_nothing() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (_id, _user, _token) = create_invitation(
        &db,
        &env,
        scope,
        "silent-create@example.test",
        InvitationCredentialType::Password,
        3_600_000_000,
    )
    .await;

    assert!(
        queued_events(&db, scope).await.is_empty(),
        "a create with no event must not invent one"
    );
}
