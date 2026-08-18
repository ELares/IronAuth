// SPDX-License-Identifier: MIT OR Apache-2.0

//! Admin user CRUD, lifecycle state machine, and external ids (issue #52), over a
//! real database (`DATABASE_URL`).
//!
//! Pins the acceptance criteria at the persistence layer: a caller-supplied id on
//! create (and its 409 collision), list pagination and the state / `external_id` /
//! identifier filters, the lifecycle state machine (every valid transition applies,
//! every invalid one is refused fail closed), the suspended-user fence (a blocked
//! user's login lookup reports a non-authenticatable state), the delete/disable
//! session cascade with its session-ended fan-out event, external-id uniqueness and
//! cross-tenant isolation and lookup, that the external id never lands in plaintext,
//! and the idempotent scheduled-offboarding execution.

use ironauth_env::Env;
use ironauth_store::idor_harness::IdorHarness;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, CursorPosition, IdentifierType, NewAdminUser, NewSession, NewUserIdentifier,
    OffboardingSchedule, Scope, SessionId, StoreError, UniquenessMode, UserId, UserIdentifierId,
    UserListFilter, UserState,
};
use sqlx::Row;

const PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaGhhc2hoYXNo";
const FAR_FUTURE_MICROS: i64 = 4_102_444_800_000_000;

/// Create an admin user in `scope`, returning its id.
#[allow(clippy::too_many_arguments)]
async fn create_user(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    identifier: &str,
    external_id: Option<&str>,
    state: UserState,
    created_at_micros: i64,
) -> Result<UserId, StoreError> {
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .users()
        .admin_create(
            env,
            NewAdminUser {
                id: None,
                identifier,
                password_hash: Some(PASSWORD_HASH),
                claims_json: None,
                external_id,
                state,
                foreign_password_hash: None,
                foreign_password_algo: None,
                traits: None,
            },
            created_at_micros,
            None,
        )
        .await
}

/// Create a live SSO session in `scope` for `subject`.
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
                impersonation: None,
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

/// Whether a session in `scope` is now ended (revoked).
async fn session_is_ended(db: &TestDatabase, scope: Scope, id: &SessionId) -> bool {
    db.store()
        .scoped(scope)
        .session_fleet()
        .get(id)
        .await
        .expect("session get")
        .expect("session exists")
        .revoked_at_unix_micros
        .is_some()
}

/// The count of pending session-ended events in `scope`.
async fn pending_events(db: &TestDatabase, scope: Scope) -> usize {
    db.store()
        .scoped(scope)
        .session_events()
        .pending(100)
        .await
        .expect("pending events")
        .len()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// A state change carrying no offboarding wake-up.
///
/// These tests drive `execute_scheduled_offboardings` by hand, so the delayed message a
/// production schedule also enqueues is deliberately absent here; the executor is what is
/// under test, not the wake-up that triggers it.
fn sched(at_unix_micros: Option<i64>) -> OffboardingSchedule<'static> {
    OffboardingSchedule {
        at_unix_micros,
        wake_payload: None,
    }
}

#[tokio::test]
async fn create_read_supports_caller_supplied_id_and_collision_is_a_conflict() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x52);
    let scope = db.seed_scope(&env).await;

    // A caller-supplied id is honored on create and read back.
    let supplied = UserId::generate(&env, &scope);
    let created = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .users()
        .admin_create(
            &env,
            NewAdminUser {
                id: Some(&supplied),
                identifier: "ada@example.test",
                password_hash: Some(PASSWORD_HASH),
                claims_json: None,
                external_id: Some("crm-1"),
                state: UserState::Active,
                foreign_password_hash: None,
                foreign_password_algo: None,
                traits: None,
            },
            1_000,
            None,
        )
        .await
        .expect("create with supplied id");
    assert_eq!(created, supplied, "the supplied id is honored");

    let record = db
        .store()
        .scoped(scope)
        .users()
        .get(&supplied)
        .await
        .expect("get");
    assert_eq!(record.identifier, "ada@example.test");
    assert_eq!(record.state, UserState::Active);
    assert_eq!(record.external_id.as_deref(), Some("crm-1"));

    // A second create with the SAME supplied id is a conflict (a 409).
    let again = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .users()
        .admin_create(
            &env,
            NewAdminUser {
                id: Some(&supplied),
                identifier: "other@example.test",
                password_hash: Some(PASSWORD_HASH),
                claims_json: None,
                external_id: None,
                state: UserState::Active,
                foreign_password_hash: None,
                foreign_password_algo: None,
                traits: None,
            },
            2_000,
            None,
        )
        .await;
    assert!(
        matches!(again, Err(StoreError::Conflict)),
        "id collision is a conflict"
    );

    // A duplicate login handle is likewise a conflict.
    let dup_handle = create_user(
        &db,
        &env,
        scope,
        "ada@example.test",
        None,
        UserState::Active,
        3_000,
    )
    .await;
    assert!(
        matches!(dup_handle, Err(StoreError::Conflict)),
        "duplicate handle is a conflict"
    );
}

#[tokio::test]
async fn list_paginates_and_filters_by_state_external_id_and_identifier() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x53);
    let scope = db.seed_scope(&env).await;

    let u_active = create_user(
        &db,
        &env,
        scope,
        "a@example.test",
        Some("ext-a"),
        UserState::Active,
        1_000,
    )
    .await
    .expect("create a");
    let _u_blocked = create_user(
        &db,
        &env,
        scope,
        "b@example.test",
        None,
        UserState::Blocked,
        2_000,
    )
    .await
    .expect("create b");
    let u_disabled = create_user(
        &db,
        &env,
        scope,
        "c@example.test",
        None,
        UserState::Disabled,
        3_000,
    )
    .await
    .expect("create c");

    // A full list returns all three, oldest first, with an accurate walk.
    let users = db.store().scoped(scope).users();
    let page1 = users
        .list(UserListFilter::default(), 2, None)
        .await
        .expect("page1");
    assert_eq!(page1.len(), 2, "page size honored");
    let cursor = CursorPosition {
        created_at_unix_micros: page1[1].created_at_unix_micros,
        id: page1[1].id.to_string(),
    };
    let page2 = users
        .list(UserListFilter::default(), 2, Some(&cursor))
        .await
        .expect("page2");
    assert_eq!(page2.len(), 1, "the third user is on the second page");
    assert_eq!(
        page2[0].id, u_disabled,
        "no loss or duplication across pages"
    );

    // Filter by state.
    let disabled = users
        .list(
            UserListFilter {
                state: Some(UserState::Disabled),
                ..Default::default()
            },
            10,
            None,
        )
        .await
        .expect("filter state");
    assert_eq!(disabled.len(), 1);
    assert_eq!(disabled[0].id, u_disabled);

    // Filter by external id.
    let by_ext = users
        .list(
            UserListFilter {
                external_id: Some("ext-a"),
                ..Default::default()
            },
            10,
            None,
        )
        .await
        .expect("filter external_id");
    assert_eq!(by_ext.len(), 1);
    assert_eq!(by_ext[0].id, u_active);

    // Filter by identifier.
    let by_ident = users
        .list(
            UserListFilter {
                identifier: Some("c@example.test"),
                ..Default::default()
            },
            10,
            None,
        )
        .await
        .expect("filter identifier");
    assert_eq!(by_ident.len(), 1);
    assert_eq!(by_ident[0].id, u_disabled);
}

#[tokio::test]
async fn the_lifecycle_state_machine_accepts_valid_transitions_and_refuses_invalid_ones() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x54);
    let scope = db.seed_scope(&env).await;
    let id = create_user(
        &db,
        &env,
        scope,
        "u@example.test",
        None,
        UserState::Active,
        1_000,
    )
    .await
    .expect("create");

    let acting = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env));

    // active -> blocked (valid).
    acting
        .users()
        .set_state(&env, &id, UserState::Blocked, sched(None), false, None)
        .await
        .expect("block");
    assert_eq!(
        db.store()
            .scoped(scope)
            .users()
            .get(&id)
            .await
            .unwrap()
            .state,
        UserState::Blocked
    );

    // blocked -> active (valid).
    acting
        .users()
        .set_state(&env, &id, UserState::Active, sched(None), false, None)
        .await
        .expect("reactivate");

    // A no-op transition (active -> active) is refused fail closed.
    let noop = acting
        .users()
        .set_state(&env, &id, UserState::Active, sched(None), false, None)
        .await;
    assert!(
        matches!(noop, Err(StoreError::Conflict)),
        "a no-op transition is invalid"
    );

    // A move INTO pending_verification is refused (a creation-only state).
    let into_pending = acting
        .users()
        .set_state(
            &env,
            &id,
            UserState::PendingVerification,
            sched(None),
            false,
            None,
        )
        .await;
    assert!(
        matches!(into_pending, Err(StoreError::Conflict)),
        "pending_verification is not a transition target"
    );

    // scheduled_offboarding requires a timestamp; without one it is refused.
    let no_ts = acting
        .users()
        .set_state(
            &env,
            &id,
            UserState::ScheduledOffboarding,
            sched(None),
            false,
            None,
        )
        .await;
    assert!(
        matches!(no_ts, Err(StoreError::Conflict)),
        "scheduled_offboarding needs a timestamp"
    );

    // A non-scheduled target must NOT carry a timestamp.
    let stray_ts = acting
        .users()
        .set_state(&env, &id, UserState::Disabled, sched(Some(10)), false, None)
        .await;
    assert!(
        matches!(stray_ts, Err(StoreError::Conflict)),
        "only scheduled_offboarding takes a timestamp"
    );

    // A transition on an absent user is the uniform not-found.
    let ghost = UserId::generate(&env, &scope);
    let absent = acting
        .users()
        .set_state(&env, &ghost, UserState::Blocked, sched(None), false, None)
        .await;
    assert!(
        matches!(absent, Err(StoreError::NotFound)),
        "absent user is not-found"
    );
}

#[tokio::test]
async fn a_suspended_user_cannot_authenticate() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x55);
    let scope = db.seed_scope(&env).await;
    let id = create_user(
        &db,
        &env,
        scope,
        "fence@example.test",
        None,
        UserState::Active,
        1_000,
    )
    .await
    .expect("create");

    // Active: the login lookup resolves and the state permits authentication.
    let active = db
        .store()
        .scoped(scope)
        .users()
        .by_identifier("fence@example.test")
        .await
        .unwrap()
        .unwrap();
    assert!(
        active.state.can_authenticate(),
        "an active user can authenticate"
    );

    // Block the user: the login lookup still resolves it (so the fence can spend
    // password time), but its state refuses authentication.
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .users()
        .set_state(&env, &id, UserState::Blocked, sched(None), false, None)
        .await
        .expect("block");
    let blocked = db
        .store()
        .scoped(scope)
        .users()
        .by_identifier("fence@example.test")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        blocked.id, id,
        "the fenced lookup still resolves the same user"
    );
    assert_eq!(blocked.state, UserState::Blocked);
    assert!(
        !blocked.state.can_authenticate(),
        "a blocked user is fenced"
    );
}

#[tokio::test]
async fn disabling_and_deleting_a_user_cascades_the_users_sessions() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x56);
    let scope = db.seed_scope(&env).await;

    // Disable path: a blocked user's live sessions end and a session-ended event
    // is published (which drives back-channel logout).
    let disabled_user = create_user(
        &db,
        &env,
        scope,
        "disable@example.test",
        None,
        UserState::Active,
        1_000,
    )
    .await
    .expect("create");
    let s1 = create_session(&db, &env, scope, &disabled_user.to_string()).await;
    assert_eq!(
        pending_events(&db, scope).await,
        0,
        "no events before the transition"
    );
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .users()
        .set_state(
            &env,
            &disabled_user,
            UserState::Disabled,
            sched(None),
            false,
            None,
        )
        .await
        .expect("disable");
    assert!(
        session_is_ended(&db, scope, &s1).await,
        "disabling ends the session"
    );
    assert_eq!(
        pending_events(&db, scope).await,
        1,
        "one session-ended event fanned out"
    );

    // Delete path: the same cascade, then the user reads as not-found and its login
    // lookup resolves absent.
    let deleted_user = create_user(
        &db,
        &env,
        scope,
        "delete@example.test",
        None,
        UserState::Active,
        2_000,
    )
    .await
    .expect("create");
    let s2 = create_session(&db, &env, scope, &deleted_user.to_string()).await;
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .users()
        .delete(&env, &deleted_user, false, None, None)
        .await
        .expect("delete");
    assert!(
        session_is_ended(&db, scope, &s2).await,
        "deleting ends the session"
    );
    assert_eq!(
        pending_events(&db, scope).await,
        2,
        "the delete fanned out a second event"
    );
    assert!(
        matches!(
            db.store().scoped(scope).users().get(&deleted_user).await,
            Err(StoreError::NotFound)
        ),
        "a deleted user reads as not-found"
    );
    assert!(
        db.store()
            .scoped(scope)
            .users()
            .by_identifier("delete@example.test")
            .await
            .unwrap()
            .is_none(),
        "a deleted user's login lookup resolves absent"
    );

    // A repeat delete of the tombstoned user is the uniform not-found.
    let repeat = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .users()
        .delete(&env, &deleted_user, false, None, None)
        .await;
    assert!(
        matches!(repeat, Err(StoreError::NotFound)),
        "a repeat delete is not-found"
    );
}

#[tokio::test]
async fn state_for_subject_reports_the_live_state_and_fails_closed_after_delete() {
    // The refresh-grant fence (issue #52) resolves a token subject's lifecycle state
    // by id: an active user is authenticatable; block/disable report a
    // non-authenticatable state; a soft-deleted user reads as absent (fail closed).
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5c);
    let scope = db.seed_scope(&env).await;

    let user = create_user(
        &db,
        &env,
        scope,
        "state@example.test",
        None,
        UserState::Active,
        1_000,
    )
    .await
    .expect("create");
    let subject = user.to_string();

    let active = db
        .store()
        .scoped(scope)
        .users()
        .state_for_subject(&subject)
        .await
        .expect("read state");
    assert_eq!(
        active,
        Some(UserState::Active),
        "an active user reports active"
    );
    assert!(
        active.expect("state").can_authenticate(),
        "an active user is authenticatable"
    );

    for fenced in [UserState::Blocked, UserState::Disabled] {
        db.store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .users()
            .set_state(&env, &user, fenced, sched(None), false, None)
            .await
            .expect("transition");
        let state = db
            .store()
            .scoped(scope)
            .users()
            .state_for_subject(&subject)
            .await
            .expect("read state");
        assert_eq!(state, Some(fenced), "the fenced state is reported");
        assert!(
            !state.expect("state").can_authenticate(),
            "a {fenced:?} user is not authenticatable"
        );
    }

    // A well-formed but absent subject in this scope is None (fail closed).
    let absent = UserId::generate(&env, &scope).to_string();
    assert_eq!(
        db.store()
            .scoped(scope)
            .users()
            .state_for_subject(&absent)
            .await
            .expect("read state"),
        None,
        "an absent subject reads as None"
    );

    // A soft-deleted user reads as None: the tombstone is fenced, not authenticatable.
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .users()
        .delete(&env, &user, false, None, None)
        .await
        .expect("delete");
    assert_eq!(
        db.store()
            .scoped(scope)
            .users()
            .state_for_subject(&subject)
            .await
            .expect("read state"),
        None,
        "a deleted user's subject reads as None (fail closed)"
    );
}

#[tokio::test]
async fn external_ids_are_unique_per_scope_isolated_across_tenants_and_lookup_able() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x57);
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;

    // A claims an external id at creation.
    let a_user = create_user(
        &db,
        &env,
        scope_a,
        "a@example.test",
        Some("shared-ext"),
        UserState::Active,
        1_000,
    )
    .await
    .expect("create a");

    // A SECOND user in the same scope cannot claim the same external id.
    let a_dup = create_user(
        &db,
        &env,
        scope_a,
        "a2@example.test",
        Some("shared-ext"),
        UserState::Active,
        2_000,
    )
    .await;
    assert!(
        matches!(a_dup, Err(StoreError::Conflict)),
        "a second claim of the external id is refused"
    );

    // The SAME external-id string in ANOTHER tenant maps to a DIFFERENT user (no
    // cross-tenant collision, no leak).
    let b_user = create_user(
        &db,
        &env,
        scope_b,
        "b@example.test",
        Some("shared-ext"),
        UserState::Active,
        3_000,
    )
    .await
    .expect("create b with the same external id string");
    assert_ne!(
        a_user, b_user,
        "the same external id string is two different users across tenants"
    );

    // Lookup by external id resolves within scope, and never across it.
    let found_a = db
        .store()
        .scoped(scope_a)
        .users()
        .by_external_id("shared-ext")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found_a.id, a_user);
    let found_b = db
        .store()
        .scoped(scope_b)
        .users()
        .by_external_id("shared-ext")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found_b.id, b_user);
    // A's lookup never resolves B's user, even for the identical external-id string.
    assert_ne!(found_a.id, found_b.id);

    // Unlink frees the external id for another user in the scope.
    db.store()
        .scoped(scope_a)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .users()
        .unlink_external_id(&env, &a_user)
        .await
        .expect("unlink");
    assert!(
        db.store()
            .scoped(scope_a)
            .users()
            .by_external_id("shared-ext")
            .await
            .unwrap()
            .is_none(),
        "the external id no longer resolves after an unlink"
    );
    let a_relink = create_user(
        &db,
        &env,
        scope_a,
        "a3@example.test",
        Some("shared-ext"),
        UserState::Active,
        4_000,
    )
    .await;
    assert!(
        a_relink.is_ok(),
        "the freed external id can be claimed again"
    );
}

#[tokio::test]
async fn the_external_id_is_never_stored_in_plaintext() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x58);
    let scope = db.seed_scope(&env).await;
    let id = create_user(
        &db,
        &env,
        scope,
        "pii@example.test",
        Some("secret-ext-id"),
        UserState::Active,
        1_000,
    )
    .await
    .expect("create");

    // The "database dump" a stolen backup would expose: the external-id columns
    // carry neither the plaintext value nor a reversible hash of it.
    let row = sqlx::query(
        "SELECT external_id_bidx, external_id_sealed FROM users \
         WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
    )
    .bind(id.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("dump");
    let bidx: Vec<u8> = row.get("external_id_bidx");
    let sealed: Vec<u8> = row.get("external_id_sealed");
    assert!(
        !contains(&sealed, b"secret-ext-id"),
        "the sealed external id is not plaintext"
    );
    assert!(
        !contains(&bidx, b"secret-ext-id"),
        "the blind index is not the plaintext value"
    );
    assert_eq!(bidx.len(), 32, "the blind index is a full HMAC-SHA256 tag");
    // The value still round-trips on read (opened under the DEK).
    assert_eq!(
        db.store()
            .scoped(scope)
            .users()
            .get(&id)
            .await
            .unwrap()
            .external_id
            .as_deref(),
        Some("secret-ext-id")
    );
}

#[tokio::test]
async fn scheduled_offboarding_executes_at_its_timestamp_and_is_idempotent() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x59);
    let scope = db.seed_scope(&env).await;
    let id = create_user(
        &db,
        &env,
        scope,
        "off@example.test",
        None,
        UserState::Active,
        1_000,
    )
    .await
    .expect("create");
    let session = create_session(&db, &env, scope, &id.to_string()).await;

    // Schedule the offboarding for an instant in the past (10 micros).
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .users()
        .set_state(
            &env,
            &id,
            UserState::ScheduledOffboarding,
            sched(Some(10)),
            false,
            None,
        )
        .await
        .expect("schedule offboarding");
    assert_eq!(
        db.store()
            .scoped(scope)
            .users()
            .get(&id)
            .await
            .unwrap()
            .state,
        UserState::ScheduledOffboarding
    );
    // Still authenticatable while merely scheduled.
    assert!(
        db.store()
            .scoped(scope)
            .users()
            .get(&id)
            .await
            .unwrap()
            .state
            .can_authenticate()
    );

    // A worker pass with a "now" past the scheduled instant executes it: the user is
    // disabled and its session cascaded, exactly as a manual disable.
    let executed = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .users()
        .execute_scheduled_offboardings(&env, 1_000_000)
        .await
        .expect("execute");
    assert_eq!(executed, 1, "one due user was offboarded");
    assert_eq!(
        db.store()
            .scoped(scope)
            .users()
            .get(&id)
            .await
            .unwrap()
            .state,
        UserState::Disabled
    );
    assert!(
        session_is_ended(&db, scope, &session).await,
        "the offboarding cascaded the session"
    );

    // Idempotent: a second pass reprocesses nothing (the user is no longer scheduled).
    let again = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .users()
        .execute_scheduled_offboardings(&env, 2_000_000)
        .await
        .expect("execute again");
    assert_eq!(again, 0, "the second pass reprocesses nothing");
}

#[tokio::test]
async fn idor_harness_denies_cross_scope_user_surfaces_uniformly() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5a);

    // Caller is tenant A; victims live in tenant B and in a second environment of A.
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let env_a2 = db.seed_environment(&env, scope_a.tenant()).await;
    let scope_a2 = Scope::new(scope_a.tenant(), env_a2);

    let victim_b = create_user(
        &db,
        &env,
        scope_b,
        "vb@example.test",
        Some("vb-external-id"),
        UserState::Active,
        1_000,
    )
    .await
    .expect("victim b");
    let victim_a2 = create_user(
        &db,
        &env,
        scope_a2,
        "va2@example.test",
        None,
        UserState::Active,
        2_000,
    )
    .await
    .expect("victim a2");
    // A login identifier on victim B, so the identifier probes hunt a foreign row of
    // their OWN key type rather than being vacuous, the same discipline the external-id
    // and by-identifier probes already follow below.
    let victim_identifier = UserIdentifierId::generate(&env, &scope_b);
    db.store()
        .scoped(scope_b)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .user_identifiers()
        .add(
            &env,
            NewUserIdentifier {
                id: &victim_identifier,
                user_id: &victim_b,
                identifier_type: IdentifierType::Email,
                raw: "vb-identifier@example.test",
                verified: false,
                mode: UniquenessMode::EnvironmentWide,
                org: None,
            },
            None,
        )
        .await
        .expect("seed victim b's login identifier");

    // A well-formed but absent id in the caller's OWN scope: the uniformity baseline.
    let absent_in_a = UserId::generate(&env, &scope_a).to_string();

    let mut harness = IdorHarness::new();
    harness.register_user_admin_probes();
    assert_eq!(
        harness.probe_names(),
        vec![
            "users.get",
            "users.list",
            "users.by_external_id",
            "users.delete",
            "users.set_state",
            "users.update_claims",
            "users.external_id.link",
            "users.external_id.unlink",
            "users.state_for_subject",
            "users.claims_for_subject",
            "users.by_identifier",
            "user_identifiers.list_for_user",
            "user_identifiers.add",
        ],
        "every scope-embedding user surface is registered, the by-subject data-plane \
         reads included (issue #241) and the flexible login-identifier surface too \
         (issue #54, epic #514)"
    );

    // The foreign references include victim B's REAL external-id value AND its REAL login
    // identifier, so the by_external_id and by_identifier probes each hunt a foreign row
    // of their OWN key type (a cross-tenant lookup must resolve none) rather than being
    // vacuous. The two `usr_` ids carry the id-keyed probes, state_for_subject and
    // claims_for_subject among them.
    let foreign = [
        victim_b.to_string(),
        victim_a2.to_string(),
        "vb-external-id".to_owned(),
        "vb@example.test".to_owned(),
        absent_in_a,
    ];
    let foreign_refs: Vec<&str> = foreign.iter().map(String::as_str).collect();
    let leaks = harness.run(db.store(), scope_a, &foreign_refs).await;
    assert!(
        leaks.is_empty(),
        "cross-scope user leak detected: {leaks:?}"
    );

    // The probes above all report `Denied`, and `Denied` is also what a probe hunting a
    // row that was never planted reports. So every keyed READ gets a positive control: the
    // victim's OWN scope resolves the identical argument that read nothing under the
    // caller's. See the helper for what that does and does not cover.
    assert_every_keyed_read_resolves_in_its_own_scope(&db, scope_b, &victim_b.to_string()).await;

    // The identifier list probe's own positive control: the SAME read that returned
    // nothing under the caller resolves under the victim's scope. Without it a leak-free
    // score here would be indistinguishable from a user that simply has no identifiers.
    let own_scope = db
        .store()
        .scoped(scope_b)
        .user_identifiers()
        .list_for_user(&victim_b)
        .await
        .expect("victim b's own scope lists its identifiers");
    assert_eq!(
        own_scope.len(),
        1,
        "the identifier the caller could not see is really there in the victim's scope"
    );

    // And the identifier MUTATION probe changed nothing: exactly one row, the seeded one,
    // with its value intact, so `user_identifiers.add` planted no handle on the foreign
    // account.
    assert_eq!(own_scope[0].id, victim_identifier);
    assert_eq!(own_scope[0].raw, "vb-identifier@example.test");
}

/// The non-vacuity half of `idor_harness_denies_cross_scope_user_surfaces_uniformly`.
///
/// Each of the FIVE keyed user READS (`users.get`, `users.by_external_id`,
/// `users.state_for_subject`, `users.claims_for_subject`, `users.by_identifier`) is driven
/// under the VICTIM's scope with the same argument the harness just drove cross-scope, and
/// each must resolve. Without this the whole suite would score a clean pass against a user
/// that does not exist: `Denied` is the outcome for "the scope filter refused" and for
/// "there was nothing there", and only this tells them apart.
///
/// # What this does NOT control, stated rather than implied
///
/// The harness registers THIRTEEN probes. Twelve are keyed; `users.list` is the one that is
/// not (it takes no key, and its foreign row is asserted absent from a page that is
/// otherwise populated, which is its own non-vacuity argument). Of the twelve keyed probes,
/// six are reads and six are MUTATIONS: `users.delete`, `users.set_state`,
/// `users.update_claims`, `users.external_id.link`, `users.external_id.unlink` and
/// `user_identifiers.add`.
///
/// The sixth keyed read is `user_identifiers.list_for_user`, and its control is not in this
/// helper: it lives inline at the end of the test, because it reads a DIFFERENT table and
/// asserts a row count rather than a resolution. `user_identifiers.add` is also the one
/// MUTATION in the suite that gets a direct control, for a reason the note below says the
/// user mutations cannot have: planting a login identifier does not destroy the user row
/// the read controls depend on, so the seeded identifier is simply re-read afterwards and
/// asserted to be the only one.
///
/// The five mutations get no control of this shape, and cannot: driving one under the
/// victim's own scope to prove it "resolves" would DELETE, BLOCK, or REWRITE the very row
/// the read controls above are asserting they can still see, so the controls would have to
/// be ordered against each other and the fixture would no longer be a fixed point. Their
/// non-vacuity rests on something else: each takes the same `usr_` id the read probes take,
/// and `users.get` is proven above to resolve that exact id in the victim's scope, so the
/// argument every mutation probe is handed is a key that names a real row. That is weaker
/// than a control and it is written down here rather than left as a silent gap.
async fn assert_every_keyed_read_resolves_in_its_own_scope(
    db: &TestDatabase,
    victim_scope: Scope,
    victim: &str,
) {
    let users = || db.store().scoped(victim_scope).users();
    // `users.get`, the id-keyed management read. It carried no control until issue #241's
    // fold, which is why the sentence above used to say "every keyed probe" while naming
    // four of five: the probe that reads a user BY ITS ID, the plainest one in the set, was
    // the one nobody had proved was hunting a planted row.
    let victim_id = users().parse_id(victim).expect("the victim id parses");
    assert!(
        users().get(&victim_id).await.is_ok(),
        "tenant B reads its own user by id (the probe hunts a real row)"
    );
    assert!(
        users()
            .by_external_id("vb-external-id")
            .await
            .expect("external id read")
            .is_some(),
        "tenant B resolves its own user by external id (the probe hunts a real row)"
    );
    assert!(
        users()
            .state_for_subject(victim)
            .await
            .expect("state read")
            .is_some(),
        "tenant B reads its own user's lifecycle state (the probe hunts a real row)"
    );
    assert!(
        users()
            .claims_for_subject(victim)
            .await
            .expect("claims read")
            .is_some(),
        "tenant B opens its own user's claim document (the probe hunts a real row)"
    );
    assert!(
        users()
            .by_identifier("vb@example.test")
            .await
            .expect("identifier read")
            .is_some(),
        "tenant B resolves its own user by login handle (the probe hunts a real row)"
    );
}

/// Deleting a user emits `user.deleted` onto the webhook event queue, in the SAME transaction
/// as the tombstone (issue #108).
///
/// `user.deleted` had been a subscription FILTER string in the webhook surface with nothing
/// emitting it, so an operator could subscribe to it and wait forever. This is the producer,
/// and this is what says it exists.
///
/// The envelope is validated through `event_catalog::validate_event`, which is the SAME
/// function the fan-out consumer calls before creating a single delivery. Asserting the row
/// is present without validating it would pass for an event the fan-out then refuses
/// permanently -- enqueued, undeliverable, and silent.
#[tokio::test]
async fn deleting_a_user_emits_the_registered_user_deleted_event() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let user = create_user(
        &db,
        &env,
        scope,
        "deleted-event@example.test",
        None,
        UserState::Active,
        1_000,
    )
    .await
    .expect("create");

    assert_eq!(
        webhook_events(&db, scope).await.len(),
        0,
        "no event exists before the delete, so a later one is caused by it"
    );

    let envelope = serde_json::json!({
        "id": "evt_user_deleted_1",
        "type": "user.deleted",
        "payload_schema_version": 1,
        "occurred_at_unix_ms": 1_i64,
        "tenant_id": scope.tenant().to_string(),
        "environment_id": scope.environment().to_string(),
        "payload": { "user_id": user.to_string(), "hard_kill": false },
    });
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .users()
        .delete(
            &env,
            &user,
            false,
            None,
            Some(&ironauth_store::DomainEvent {
                id: "evt_user_deleted_1",
                subject: &user.to_string(),
                envelope: &envelope,
            }),
        )
        .await
        .expect("delete");

    let events = webhook_events(&db, scope).await;
    assert_eq!(events.len(), 1, "the delete enqueues exactly one event");
    assert_eq!(events[0]["type"], "user.deleted", "{:?}", events[0]);
    assert_eq!(events[0]["payload"]["user_id"], user.to_string());
    assert_eq!(
        events[0]["payload"]["hard_kill"], false,
        "the payload records WHICH delete happened, not just that one did"
    );
    ironauth_store::event_catalog::validate_event(&events[0])
        .expect("the emitted envelope validates against the registry the fan-out enforces");
}

/// A delete that carries no event enqueues nothing.
///
/// The paired negative. Without it the test above passes for a delete that enqueues an event
/// unconditionally, which would emit one for every internal caller that passes `None` --
/// including the cascade paths that are not management deletes at all.
#[tokio::test]
async fn a_delete_with_no_event_enqueues_nothing() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let user = create_user(
        &db,
        &env,
        scope,
        "no-event@example.test",
        None,
        UserState::Active,
        1_000,
    )
    .await
    .expect("create");

    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .users()
        .delete(&env, &user, false, None, None)
        .await
        .expect("delete");

    assert_eq!(
        webhook_events(&db, scope).await.len(),
        0,
        "a delete with no event must not invent one"
    );
}

/// Every webhook-event envelope currently queued in `scope`.
async fn webhook_events(db: &TestDatabase, scope: Scope) -> Vec<serde_json::Value> {
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

/// A claims update emits `user.updated` naming the field it wrote (issue #108).
///
/// Like `user.deleted`, this was a subscription filter string the webhook surface advertised
/// and nothing emitted. `fields` names WHAT changed because a receiver told only that "the
/// user changed" has to re-read the whole user to find out, which is the work the event
/// exists to save.
#[tokio::test]
async fn updating_claims_emits_user_updated_naming_the_field() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let user = create_user(
        &db,
        &env,
        scope,
        "updated-claims@example.test",
        None,
        UserState::Active,
        1_000,
    )
    .await
    .expect("create");

    assert_eq!(
        webhook_events(&db, scope).await.len(),
        0,
        "no event exists before the update"
    );

    let envelope = serde_json::json!({
        "id": "evt_user_updated_claims",
        "type": "user.updated",
        "payload_schema_version": 1,
        "occurred_at_unix_ms": 1_i64,
        "tenant_id": scope.tenant().to_string(),
        "environment_id": scope.environment().to_string(),
        "payload": { "user_id": user.to_string(), "fields": ["claims"] },
    });
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .users()
        .update_claims(
            &env,
            &user,
            r#"{"department":"engineering"}"#,
            Some(&ironauth_store::DomainEvent {
                id: "evt_user_updated_claims",
                subject: &user.to_string(),
                envelope: &envelope,
            }),
        )
        .await
        .expect("update claims");

    let events = webhook_events(&db, scope).await;
    assert_eq!(
        events.len(),
        1,
        "the claims write enqueues exactly one event"
    );
    assert_eq!(events[0]["type"], "user.updated");
    assert_eq!(
        events[0]["payload"]["fields"],
        serde_json::json!(["claims"]),
        "the event names the field that was written"
    );
    ironauth_store::event_catalog::validate_event(&events[0])
        .expect("the emitted envelope validates against the registry the fan-out enforces");
}

/// A claims update carrying no event enqueues nothing.
///
/// The paired negative: without it the test above passes for a write that emits
/// unconditionally, which would fire for every internal caller that passes `None`.
#[tokio::test]
async fn a_claims_update_with_no_event_enqueues_nothing() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let user = create_user(
        &db,
        &env,
        scope,
        "silent-claims@example.test",
        None,
        UserState::Active,
        1_000,
    )
    .await
    .expect("create");

    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .users()
        .update_claims(&env, &user, r#"{"department":"sales"}"#, None)
        .await
        .expect("update claims");

    assert_eq!(
        webhook_events(&db, scope).await.len(),
        0,
        "a write with no event must not invent one"
    );
}

/// The registry rejects a `user.updated` whose `fields` names something that is not a field
/// this producer writes.
///
/// The schema's `enum` is the contract a receiver switches on. Without this assertion the
/// enum could be widened, or dropped, and nothing would notice until a consumer met a value
/// it had no branch for.
#[tokio::test]
async fn user_updated_refuses_a_field_outside_the_declared_set() {
    let scope_tenant = "ten_x";
    let bad = serde_json::json!({
        "id": "evt_bad",
        "type": "user.updated",
        "payload_schema_version": 1,
        "occurred_at_unix_ms": 1_i64,
        "tenant_id": scope_tenant,
        "environment_id": "env_y",
        "payload": { "user_id": "usr_1", "fields": ["password"] },
    });
    assert!(
        ironauth_store::event_catalog::validate_event(&bad).is_err(),
        "an undeclared field must not validate"
    );

    let good = serde_json::json!({
        "id": "evt_good",
        "type": "user.updated",
        "payload_schema_version": 1,
        "occurred_at_unix_ms": 1_i64,
        "tenant_id": scope_tenant,
        "environment_id": "env_y",
        "payload": { "user_id": "usr_1", "fields": ["traits"] },
    });
    ironauth_store::event_catalog::validate_event(&good)
        .expect("a declared field validates, so the refusal above is about the VALUE");
}

/// A user state change emits `user.state_changed`, in the same transaction as the session
/// cascade it triggers (issue #108).
///
/// This is the DEPROVISIONING event: a state that ends sessions kills every live one in this
/// transaction, and downstream systems act on the notice. The grouping matters in a specific
/// direction -- a receiver told about a suspension that then rolled back would revoke
/// downstream access for an account still able to log in.
#[tokio::test]
async fn a_user_state_change_emits_the_registered_event_with_the_cascade() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let user = create_user(
        &db,
        &env,
        scope,
        "state-change@example.test",
        None,
        UserState::Active,
        1_000,
    )
    .await
    .expect("create");

    assert_eq!(
        webhook_events(&db, scope).await.len(),
        0,
        "creating a user emits nothing here, so the state change's event is unambiguous"
    );

    let envelope = ironauth_store::event_catalog::envelope(
        "evt_user_state",
        "user.state_changed",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        1,
        &serde_json::json!({
            "user_id": user.to_string(),
            "state": "blocked",
            "hard_kill": false,
        }),
    )
    .expect("user.state_changed is registered");

    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .users()
        .set_state_with_event(
            &env,
            &user,
            UserState::Blocked,
            sched(None),
            false,
            None,
            Some(&ironauth_store::DomainEvent {
                id: "evt_user_state",
                subject: &user.to_string(),
                envelope: &envelope,
            }),
        )
        .await
        .expect("set state with event");

    let events = webhook_events(&db, scope).await;
    assert_eq!(
        events.len(),
        1,
        "the state change enqueues exactly one event"
    );
    assert_eq!(events[0]["type"], "user.state_changed");
    assert_eq!(events[0]["payload"]["state"], "blocked");
    assert_eq!(
        events[0]["payload"]["hard_kill"], false,
        "hard_kill records WHICH change happened, which a receiver cannot infer later"
    );
    ironauth_store::event_catalog::validate_event(&events[0])
        .expect("the envelope validates against the registry the fan-out enforces");
}

/// A state change carrying no event enqueues nothing.
#[tokio::test]
async fn a_user_state_change_with_no_event_enqueues_nothing() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let user = create_user(
        &db,
        &env,
        scope,
        "quiet-state@example.test",
        None,
        UserState::Active,
        1_000,
    )
    .await
    .expect("create");

    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .users()
        .set_state(&env, &user, UserState::Blocked, sched(None), false, None)
        .await
        .expect("set state");

    assert_eq!(
        webhook_events(&db, scope).await.len(),
        0,
        "a state change with no event must not invent one"
    );
}

/// Linking an external id announces BOTH sides; unlinking announces only the user.
///
/// The asymmetry is forced rather than chosen. The link is GIVEN the identifier and a
/// receiver reconciling against an upstream directory needs both sides or it cannot update its
/// mapping. The unlink is given only the user -- the store clears whatever was there -- so
/// nothing knows the outgoing value when the envelope is built.
///
/// Both halves are asserted, because a producer that always carried the field, or never did,
/// would pass a test that exercised only one.
#[tokio::test]
async fn linking_an_external_id_announces_both_sides_and_unlinking_announces_the_user() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let user = create_user(
        &db,
        &env,
        scope,
        "linked@example.test",
        None,
        UserState::Active,
        1_000_000,
    )
    .await
    .expect("create user");
    let subject = user.to_string();

    let linked = ironauth_store::event_catalog::envelope(
        "evt_external_linked",
        "user.external_id_linked",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        1,
        &serde_json::json!({ "user_id": subject, "external_id": "upstream-42" }),
    )
    .expect("user.external_id_linked is registered");

    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .users()
        .link_external_id_with_event(
            &env,
            &user,
            "upstream-42",
            Some(&ironauth_store::DomainEvent {
                id: "evt_external_linked",
                subject: &subject,
                envelope: &linked,
            }),
        )
        .await
        .expect("link with event");

    let claimed = db
        .store()
        .scoped(scope)
        .outbox()
        .claim(
            &env,
            ironauth_store::WEBHOOK_EVENT_CONSUMER,
            std::time::Duration::from_secs(30),
            100,
        )
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 1, "the link enqueues exactly one event");
    assert_eq!(claimed[0].payload["type"], "user.external_id_linked");
    assert_eq!(claimed[0].payload["payload"]["external_id"], "upstream-42");
    ironauth_store::event_catalog::validate_event(&claimed[0].payload)
        .expect("the envelope validates against the registry the fan-out enforces");
    // Completed so the unlink is claimable: both carry the user id as ordering key.
    for message in &claimed {
        db.store()
            .scoped(scope)
            .outbox()
            .complete(&env, message)
            .await
            .expect("complete");
    }

    let unlinked = ironauth_store::event_catalog::envelope(
        "evt_external_unlinked",
        "user.external_id_unlinked",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        2,
        &serde_json::json!({ "user_id": subject }),
    )
    .expect("user.external_id_unlinked is registered");

    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .users()
        .unlink_external_id_with_event(
            &env,
            &user,
            Some(&ironauth_store::DomainEvent {
                id: "evt_external_unlinked",
                subject: &subject,
                envelope: &unlinked,
            }),
        )
        .await
        .expect("unlink with event");

    let after = webhook_events(&db, scope).await;
    assert_eq!(after.len(), 1, "the unlink enqueues exactly one event");
    assert_eq!(after[0]["type"], "user.external_id_unlinked");
    assert!(
        after[0]["payload"].get("external_id").is_none(),
        "the unlink cannot name an id it was never given: {}",
        after[0]
    );
    ironauth_store::event_catalog::validate_event(&after[0])
        .expect("the envelope validates against the registry the fan-out enforces");
}
