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
    CorrelationId, CursorPosition, NewAdminUser, NewSession, Scope, SessionId, StoreError, UserId,
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
        .set_state(&env, &id, UserState::Blocked, None, false, None)
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
        .set_state(&env, &id, UserState::Active, None, false, None)
        .await
        .expect("reactivate");

    // A no-op transition (active -> active) is refused fail closed.
    let noop = acting
        .users()
        .set_state(&env, &id, UserState::Active, None, false, None)
        .await;
    assert!(
        matches!(noop, Err(StoreError::Conflict)),
        "a no-op transition is invalid"
    );

    // A move INTO pending_verification is refused (a creation-only state).
    let into_pending = acting
        .users()
        .set_state(&env, &id, UserState::PendingVerification, None, false, None)
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
            None,
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
        .set_state(&env, &id, UserState::Disabled, Some(10), false, None)
        .await;
    assert!(
        matches!(stray_ts, Err(StoreError::Conflict)),
        "only scheduled_offboarding takes a timestamp"
    );

    // A transition on an absent user is the uniform not-found.
    let ghost = UserId::generate(&env, &scope);
    let absent = acting
        .users()
        .set_state(&env, &ghost, UserState::Blocked, None, false, None)
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
        .set_state(&env, &id, UserState::Blocked, None, false, None)
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
        .set_state(&env, &disabled_user, UserState::Disabled, None, false, None)
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
        .delete(&env, &deleted_user, false, None)
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
        .delete(&env, &deleted_user, false, None)
        .await;
    assert!(
        matches!(repeat, Err(StoreError::NotFound)),
        "a repeat delete is not-found"
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
            Some(10),
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
        None,
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
    // A well-formed but absent id in the caller's OWN scope: the uniformity baseline.
    let absent_in_a = UserId::generate(&env, &scope_a).to_string();

    let mut harness = IdorHarness::new();
    harness.register_user_admin_probes();
    assert_eq!(
        harness.probe_names(),
        vec![
            "users.get",
            "users.list",
            "users.delete",
            "users.set_state",
            "users.external_id.link",
        ],
        "every admin user resolve-by-id surface is registered"
    );

    let foreign = [victim_b.to_string(), victim_a2.to_string(), absent_in_a];
    let foreign_refs: Vec<&str> = foreign.iter().map(String::as_str).collect();
    let leaks = harness.run(db.store(), scope_a, &foreign_refs).await;
    assert!(
        leaks.is_empty(),
        "cross-scope user leak detected: {leaks:?}"
    );
}
