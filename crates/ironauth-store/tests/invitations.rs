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
//! across tenants; a token minted in one tenant never resolves in another; and every
//! lifecycle mutation is audited.

use std::time::{Duration, SystemTime};

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, InvitationCredentialType, InvitationId, InvitationState, MintedInvitationToken,
    NewAdminUser, NewInvitation, Scope, StoreError, UserId, UserState, invitation_token_digest,
    mint_invitation_token, mint_invitation_token_for,
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
    // Create and invitation-create are CONTROL-plane (admin) operations: the
    // migration grants INSERT on user_invitations to the control role only, exactly
    // as the admin API uses the control-plane store.
    let user_id = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .users()
        .admin_create(
            env,
            NewAdminUser {
                id: None,
                identifier,
                password_hash: None,
                claims_json: None,
                external_id: None,
                state: UserState::PendingVerification,
                foreign_password_hash: None,
                foreign_password_algo: None,
                traits_json: None,
                traits_schema_version: None,
            },
            created,
            None,
        )
        .await
        .expect("create pending user");
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .invitations()
        .create(
            env,
            NewInvitation {
                id: &id,
                user_id: &user_id,
                target_identifier: identifier,
                token_digest: &digest,
                credential_type,
                org_context: None,
                expires_at_unix_micros: created.saturating_add(ttl_micros),
            },
            created,
            None,
        )
        .await
        .expect("create invitation");
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
