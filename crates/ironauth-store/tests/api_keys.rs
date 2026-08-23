// SPDX-License-Identifier: MIT OR Apache-2.0

//! API keys and personal access tokens (issue #99), criteria 1 and 4.
//!
//! Criterion 1 says disabling an organization immediately invalidates its keys, and disabling
//! a user immediately invalidates that user's keys and PATs. There is deliberately no
//! revocation sweep at disable time: verification consults the owner's CURRENT state, so
//! "immediately" is exact rather than eventual, and a re-enable restores the keys instead of
//! having silently destroyed them.

use ironauth_store::api_key::{ApiKeyKindTag, mint_api_key};
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{ApiKeyOwner, CorrelationId, NewApiKey, Scope, UserId};

fn now_micros(env: &ironauth_env::Env) -> i64 {
    i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("after epoch")
            .as_micros(),
    )
    .expect("fits i64")
}

async fn seed_user(
    db: &TestDatabase,
    env: &ironauth_env::Env,
    scope: Scope,
    handle: &str,
) -> UserId {
    let id = UserId::generate(env, &scope);
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .users()
        .register_passwordless(env, &id, handle, None)
        .await
        .expect("register user");
    id
}

/// Mint a key for `owner` through the control plane and return its plaintext.
async fn issue(
    db: &TestDatabase,
    env: &ironauth_env::Env,
    scope: Scope,
    owner: &ApiKeyOwner,
    kind: ApiKeyKindTag,
) -> String {
    let minted = mint_api_key(env, &scope, kind);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .api_keys()
        .create(
            env,
            NewApiKey {
                id: &minted.id,
                key_digest: &minted.digest,
                owner,
                display_name: "a key",
                expires_at_unix_micros: None,
            },
            now_micros(env),
            None,
        )
        .await
        .expect("create the key");
    minted.plaintext
}

/// Criterion 4's storage half, against the engine: the plaintext appears in NO column.
///
/// Asserted over every text column of the row rather than over the one column I expect to
/// hold the digest, because the property is "nowhere", and a future column added to carry a
/// label or a hint is exactly how a plaintext ends up persisted by accident.
#[tokio::test]
async fn the_plaintext_key_is_in_no_column_of_the_row() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let user = seed_user(&db, &env, scope, "founder@example.test").await;
    let plaintext = issue(
        &db,
        &env,
        scope,
        &ApiKeyOwner::User(user),
        ApiKeyKindTag::PersonalAccessToken,
    )
    .await;

    let row: Vec<Option<String>> = sqlx::query_scalar(
        "SELECT unnest(ARRAY[key_digest, id, owner_kind, user_id, service_account_id, \
                            organization_id, display_name]) FROM api_keys \
         WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_all(db.owner_pool())
    .await
    .expect("read the row");

    let (_, secret) = plaintext.split_once('~').expect("delimiter");
    for value in row.into_iter().flatten() {
        assert_ne!(value, plaintext, "a column holds the whole key");
        assert!(
            !value.contains(secret),
            "a column holds the key's secret: {value}"
        );
    }
}

/// A live key verifies, and the record names its owner.
#[tokio::test]
async fn a_live_key_verifies_and_names_its_owner() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let user = seed_user(&db, &env, scope, "live@example.test").await;
    let owner = ApiKeyOwner::User(user);
    let plaintext = issue(&db, &env, scope, &owner, ApiKeyKindTag::PersonalAccessToken).await;

    let resolved = db
        .store()
        .scoped(scope)
        .api_keys()
        .verify(&plaintext, now_micros(&env))
        .await
        .expect("verify");
    let resolved = resolved.expect("a live key verifies");
    assert_eq!(resolved.owner, ApiKeyOwner::User(user));
}

/// Criterion 1, the user half: disabling a user invalidates that user's keys IMMEDIATELY,
/// with no sweep, and re-enabling restores them.
///
/// The restore half is the one that distinguishes this design from a revocation sweep. A
/// sweep would have set `revoked_at` and the key would stay dead after the user came back,
/// which is a silently destructive administrative action.
#[tokio::test]
async fn disabling_a_user_invalidates_their_keys_and_re_enabling_restores_them() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let user = seed_user(&db, &env, scope, "toggled@example.test").await;
    let plaintext = issue(
        &db,
        &env,
        scope,
        &ApiKeyOwner::User(user),
        ApiKeyKindTag::PersonalAccessToken,
    )
    .await;
    let verify = || async {
        db.store()
            .scoped(scope)
            .api_keys()
            .verify(&plaintext, now_micros(&env))
            .await
            .expect("verify")
    };
    assert!(verify().await.is_some(), "the key starts live");

    sqlx::query("UPDATE users SET state = 'disabled' WHERE id = $1")
        .bind(user.to_string())
        .execute(db.owner_pool())
        .await
        .expect("disable the user");
    assert!(
        verify().await.is_none(),
        "a disabled user's key must stop verifying immediately, with no sweep"
    );

    sqlx::query("UPDATE users SET state = 'active' WHERE id = $1")
        .bind(user.to_string())
        .execute(db.owner_pool())
        .await
        .expect("re-enable the user");
    assert!(
        verify().await.is_some(),
        "re-enabling must restore the key. A revocation sweep at disable time would have \
         destroyed it permanently, making an ordinary administrative toggle irreversible"
    );
}

/// Every non-authenticatable user state invalidates, not just `disabled`.
///
/// The predicate is `UserState::can_authenticate`, which is `{active, scheduled_offboarding}`.
/// Driving the whole vocabulary rather than the one state the criterion names is what makes a
/// later state addition visible here: a new state that cannot authenticate but whose keys
/// still verify is exactly the gap this catches.
#[tokio::test]
async fn only_an_authenticatable_owner_state_lets_a_key_verify() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let user = seed_user(&db, &env, scope, "states@example.test").await;
    let plaintext = issue(
        &db,
        &env,
        scope,
        &ApiKeyOwner::User(user),
        ApiKeyKindTag::PersonalAccessToken,
    )
    .await;

    for (state, may_verify) in [
        ("active", true),
        ("scheduled_offboarding", true),
        ("blocked", false),
        ("disabled", false),
        ("pending_verification", false),
        ("waitlisted", false),
    ] {
        sqlx::query("UPDATE users SET state = $2 WHERE id = $1")
            .bind(user.to_string())
            .bind(state)
            .execute(db.owner_pool())
            .await
            .unwrap_or_else(|error| panic!("set state {state}: {error}"));
        let resolved = db
            .store()
            .scoped(scope)
            .api_keys()
            .verify(&plaintext, now_micros(&env))
            .await
            .expect("verify");
        assert_eq!(
            resolved.is_some(),
            may_verify,
            "user state {state}: expected may_verify={may_verify}"
        );
    }
}

/// A revoked key never verifies again, and revoking twice writes ONE audit row.
#[tokio::test]
async fn a_revoked_key_never_verifies_and_revoking_twice_audits_once() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let user = seed_user(&db, &env, scope, "revoked@example.test").await;
    let minted = mint_api_key(&env, &scope, ApiKeyKindTag::PersonalAccessToken);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .api_keys()
        .create(
            &env,
            NewApiKey {
                id: &minted.id,
                key_digest: &minted.digest,
                owner: &ApiKeyOwner::User(user),
                display_name: "to be revoked",
                expires_at_unix_micros: None,
            },
            now_micros(&env),
            None,
        )
        .await
        .expect("create");

    for _ in 0..3 {
        db.control_store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .api_keys()
            .revoke(&env, &minted.id, now_micros(&env))
            .await
            .expect("revoke is idempotent");
    }
    assert!(
        db.store()
            .scoped(scope)
            .api_keys()
            .verify(&minted.plaintext, now_micros(&env))
            .await
            .expect("verify")
            .is_none(),
        "a revoked key must never verify again"
    );

    let revocations: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log \
         WHERE tenant_id = $1 AND environment_id = $2 AND action = 'api_key.revoked'",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("count audit rows");
    assert_eq!(
        revocations, 1,
        "three revocations, one real change, one row"
    );
}

/// An expired key does not verify, and expiry is decided by the CALLER'S clock.
#[tokio::test]
async fn an_expired_key_does_not_verify() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let user = seed_user(&db, &env, scope, "expiring@example.test").await;
    let minted = mint_api_key(&env, &scope, ApiKeyKindTag::PersonalAccessToken);
    let now = now_micros(&env);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .api_keys()
        .create(
            &env,
            NewApiKey {
                id: &minted.id,
                key_digest: &minted.digest,
                owner: &ApiKeyOwner::User(user),
                display_name: "short lived",
                expires_at_unix_micros: Some(now + 1_000_000),
            },
            now,
            None,
        )
        .await
        .expect("create");

    let repo = db.store().scoped(scope);
    assert!(
        repo.api_keys()
            .verify(&minted.plaintext, now)
            .await
            .expect("verify")
            .is_some(),
        "the key is live before its expiry"
    );
    assert!(
        repo.api_keys()
            .verify(&minted.plaintext, now + 2_000_000)
            .await
            .expect("verify")
            .is_none(),
        "the key is dead after its expiry"
    );
}

/// The DATA plane cannot mint a key.
///
/// The whole reason `create` lives on the control store. The plane that verifies keys on the
/// authentication path must not be able to issue itself one.
#[tokio::test]
async fn the_data_plane_cannot_create_a_key() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let user = seed_user(&db, &env, scope, "nomint@example.test").await;
    let minted = mint_api_key(&env, &scope, ApiKeyKindTag::PersonalAccessToken);

    let outcome = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .api_keys()
        .create(
            &env,
            NewApiKey {
                id: &minted.id,
                key_digest: &minted.digest,
                owner: &ApiKeyOwner::User(user),
                display_name: "should not exist",
                expires_at_unix_micros: None,
            },
            now_micros(&env),
            None,
        )
        .await;
    assert!(
        outcome.is_err(),
        "the data plane minted an API key, so it holds INSERT on api_keys"
    );
}

/// A garbage string never reaches a digest lookup, and never verifies.
#[tokio::test]
async fn a_malformed_presentation_never_verifies() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    for presented in [
        "",
        "not-a-key",
        "ira_ak_",
        "ira_ak_akey_short~secret",
        "ira_at_tok_something~else",
    ] {
        assert!(
            db.store()
                .scoped(scope)
                .api_keys()
                .verify(presented, now_micros(&env))
                .await
                .expect("verify")
                .is_none(),
            "{presented:?} verified"
        );
    }
}

/// Rotation revokes the old key and issues the new one, and BOTH halves land.
///
/// The atomicity is the whole reason this is one operation. Create-first leaves two live keys
/// on a crash, so a rotation performed to contain a leak has left the leaked key working;
/// revoke-first leaves none, so a routine rotation has locked the caller out.
#[tokio::test]
async fn rotation_kills_the_old_key_and_issues_the_new_one() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let user = seed_user(&db, &env, scope, "rotating@example.test").await;
    let owner = ApiKeyOwner::User(user);

    let first = mint_api_key(&env, &scope, ApiKeyKindTag::PersonalAccessToken);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .api_keys()
        .create(
            &env,
            NewApiKey {
                id: &first.id,
                key_digest: &first.digest,
                owner: &owner,
                display_name: "original",
                expires_at_unix_micros: None,
            },
            now_micros(&env),
            None,
        )
        .await
        .expect("create the original");

    let second = mint_api_key(&env, &scope, ApiKeyKindTag::PersonalAccessToken);
    let rotated_at = now_micros(&env);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .api_keys()
        .rotate(
            &env,
            &first.id,
            NewApiKey {
                id: &second.id,
                key_digest: &second.digest,
                owner: &owner,
                display_name: "rotated",
                expires_at_unix_micros: None,
            },
            rotated_at,
            None,
        )
        .await
        .expect("rotate");

    let repo = db.store().scoped(scope);
    assert!(
        repo.api_keys()
            .verify(&first.plaintext, now_micros(&env))
            .await
            .expect("verify")
            .is_none(),
        "the OLD key must stop verifying, or a rotation to contain a leak left it working"
    );
    assert!(
        repo.api_keys()
            .verify(&second.plaintext, now_micros(&env))
            .await
            .expect("verify")
            .is_some(),
        "the NEW key must verify, or a routine rotation locked the caller out"
    );

    // The recorded revocation TIME is the caller's clock, not the database's.
    //
    // Verification treats any non-null `revoked_at` as revoked whatever its value, so the
    // timestamp is invisible to the decision and nothing above would notice it being wrong. A
    // mutation writing `now + 1 day` survived every other assertion in this file. It matters
    // anyway: it is what an operator reads to answer "when did we contain this", and every
    // other timestamp in this codebase comes from the application clock seam so that a test
    // under a manual clock is deterministic.
    let recorded: Option<i64> = sqlx::query_scalar(
        "SELECT (EXTRACT(EPOCH FROM revoked_at) * 1000000)::bigint FROM api_keys WHERE id = $1",
    )
    .bind(first.id.to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("read the revocation time");
    assert_eq!(
        recorded,
        Some(rotated_at),
        "the revocation time must be the clock the caller passed"
    );
}

/// Rotating from an already-revoked key is REFUSED and issues nothing.
///
/// A refusal rather than a no-op, unlike plain revoke. Answering Ok would issue a replacement
/// the caller believes replaced something live, and leave them thinking a dead key had just
/// been rotated away.
#[tokio::test]
async fn rotating_from_a_dead_key_is_refused_and_issues_nothing() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let user = seed_user(&db, &env, scope, "deadrotate@example.test").await;
    let owner = ApiKeyOwner::User(user);

    let first = mint_api_key(&env, &scope, ApiKeyKindTag::PersonalAccessToken);
    let acting = || {
        db.control_store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
    };
    acting()
        .api_keys()
        .create(
            &env,
            NewApiKey {
                id: &first.id,
                key_digest: &first.digest,
                owner: &owner,
                display_name: "original",
                expires_at_unix_micros: None,
            },
            now_micros(&env),
            None,
        )
        .await
        .expect("create");
    acting()
        .api_keys()
        .revoke(&env, &first.id, now_micros(&env))
        .await
        .expect("revoke");

    let second = mint_api_key(&env, &scope, ApiKeyKindTag::PersonalAccessToken);
    let outcome = acting()
        .api_keys()
        .rotate(
            &env,
            &first.id,
            NewApiKey {
                id: &second.id,
                key_digest: &second.digest,
                owner: &owner,
                display_name: "should not exist",
                expires_at_unix_micros: None,
            },
            now_micros(&env),
            None,
        )
        .await;
    assert!(
        matches!(outcome, Err(ironauth_store::StoreError::NotFound)),
        "rotating from a revoked key must refuse, got {outcome:?}"
    );
    assert!(
        db.store()
            .scoped(scope)
            .api_keys()
            .verify(&second.plaintext, now_micros(&env))
            .await
            .expect("verify")
            .is_none(),
        "the refused rotation issued a key anyway, so it was not atomic"
    );
}

/// The list shows every key of one owner, revoked ones included, and no other owner's.
///
/// Revoked rows are included deliberately: a rotation's point is that the old key is visible
/// next to the new one, and hiding it would leave an operator unable to tell "I revoked that"
/// from "that was never here".
#[tokio::test]
async fn the_list_shows_one_owners_keys_including_revoked_and_no_others() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let mine = ApiKeyOwner::User(seed_user(&db, &env, scope, "mine@example.test").await);
    let theirs = ApiKeyOwner::User(seed_user(&db, &env, scope, "theirs@example.test").await);

    let live = mint_api_key(&env, &scope, ApiKeyKindTag::PersonalAccessToken);
    let dead = mint_api_key(&env, &scope, ApiKeyKindTag::PersonalAccessToken);
    let foreign = mint_api_key(&env, &scope, ApiKeyKindTag::PersonalAccessToken);
    for (minted, owner, label) in [
        (&live, &mine, "live"),
        (&dead, &mine, "dead"),
        (&foreign, &theirs, "foreign"),
    ] {
        db.control_store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .api_keys()
            .create(
                &env,
                NewApiKey {
                    id: &minted.id,
                    key_digest: &minted.digest,
                    owner,
                    display_name: label,
                    expires_at_unix_micros: None,
                },
                now_micros(&env),
                None,
            )
            .await
            .expect("create");
    }
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .api_keys()
        .revoke(&env, &dead.id, now_micros(&env))
        .await
        .expect("revoke");

    let listed = db
        .store()
        .scoped(scope)
        .api_keys()
        .list_for_owner(&mine)
        .await
        .expect("list");
    let ids: Vec<String> = listed.iter().map(|record| record.id.to_string()).collect();
    assert!(ids.contains(&live.id.to_string()), "the live key is listed");
    assert!(
        ids.contains(&dead.id.to_string()),
        "the REVOKED key is listed, so a rotation is legible"
    );
    assert!(
        !ids.contains(&foreign.id.to_string()),
        "another owner's key leaked into this owner's list: {ids:?}"
    );
    assert_eq!(listed.len(), 2);

    let revoked_flag = listed
        .iter()
        .find(|record| record.id == dead.id)
        .expect("the dead key")
        .revoked_at_unix_micros;
    assert!(
        revoked_flag.is_some(),
        "the listed revoked key must carry its revocation time, or a caller cannot tell it apart"
    );
}

/// Criterion 1's ORGANIZATION half: disabling an organization invalidates its org-scoped keys.
///
/// This clause is the FIRST one the criterion states and it had no test. Every other test in
/// this file uses a user owner, so the organization branch of `verify` (which reads
/// `organizations.state` and `deleted_at`) was reached by nothing, and I reported criterion 1
/// as met on the strength of the user half alone.
///
/// Like the user case, the invalidation is immediate and reversible, because it is a read of
/// the owner's current state rather than a revocation sweep.
#[tokio::test]
async fn disabling_an_organization_invalidates_its_keys_and_enabling_restores_them() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let org = ironauth_store::OrganizationId::generate(&env, &scope);
    db.control_store()
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .organizations(scope)
        .create(&env, &org, now_micros(&env), "acme", None)
        .await
        .expect("create the organization");
    let plaintext = issue(
        &db,
        &env,
        scope,
        &ApiKeyOwner::Organization(org),
        ApiKeyKindTag::ApiKey,
    )
    .await;
    let verify = || async {
        db.store()
            .scoped(scope)
            .api_keys()
            .verify(&plaintext, now_micros(&env))
            .await
            .expect("verify")
    };
    let resolved = verify().await.expect("an org-owned key starts live");
    assert_eq!(resolved.owner, ApiKeyOwner::Organization(org));

    for (state, may_verify, why) in [
        (
            ironauth_store::OrganizationState::Disabled,
            false,
            "a disabled organization's key must stop verifying immediately",
        ),
        (
            ironauth_store::OrganizationState::Active,
            true,
            "re-enabling the organization must restore its keys, exactly as for a user",
        ),
    ] {
        db.control_store()
            .management()
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .organizations(scope)
            .set_state(&env, &org, state, None)
            .await
            .expect("set the organization state");
        assert_eq!(verify().await.is_some(), may_verify, "{why}");
    }
}

/// A SOFT-DELETED organization's keys stop verifying too.
///
/// Separate from the disabled case because it is a different column. `verify` requires both
/// `deleted_at IS NULL` and an active state, and a check of only the state would let a deleted
/// organization's keys go on working: deletion sets `deleted_at` and leaves `state` alone.
#[tokio::test]
async fn a_soft_deleted_organizations_keys_stop_verifying() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let org = ironauth_store::OrganizationId::generate(&env, &scope);
    let acting = || {
        db.control_store()
            .management()
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
    };
    acting()
        .organizations(scope)
        .create(&env, &org, now_micros(&env), "briefly here", None)
        .await
        .expect("create");
    let plaintext = issue(
        &db,
        &env,
        scope,
        &ApiKeyOwner::Organization(org),
        ApiKeyKindTag::ApiKey,
    )
    .await;
    assert!(
        db.store()
            .scoped(scope)
            .api_keys()
            .verify(&plaintext, now_micros(&env))
            .await
            .expect("verify")
            .is_some()
    );

    acting()
        .organizations(scope)
        .delete(&env, &org)
        .await
        .expect("soft delete");
    assert!(
        db.store()
            .scoped(scope)
            .api_keys()
            .verify(&plaintext, now_micros(&env))
            .await
            .expect("verify")
            .is_none(),
        "a soft-deleted organization's keys must stop verifying. Deletion leaves `state` \
         alone, so a state-only check would keep them working"
    );
}

/// A SERVICE-ACCOUNT-owned key verifies, and stops when its principal is gone.
///
/// The third owner kind, and the last one with no test. `verify` answers the service-account
/// branch on the JOIN's presence rather than on a state column, because `service_accounts`
/// carries no state and no `deleted_at`: the principal either exists or it does not.
///
/// Written because twelve user tests and two organization tests would otherwise let a reader
/// infer that all three owner kinds are covered. They were not, and the organization gap that
/// inference would have hidden was two independent authentication bypasses.
#[tokio::test]
async fn a_service_account_owned_key_verifies_and_dies_with_its_principal() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;

    // A service-account principal is minted for a CLIENT, on that client's first
    // client-credentials issuance. Reached here through the same `ensure` seam.
    let client = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .create(&env, "a machine client")
        .await
        .expect("create the client");
    let principal = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .service_accounts()
        .ensure(&env, &client)
        .await
        .expect("mint the service-account principal");

    let plaintext = issue(
        &db,
        &env,
        scope,
        &ApiKeyOwner::ServiceAccount(principal),
        ApiKeyKindTag::ApiKey,
    )
    .await;
    let resolved = db
        .store()
        .scoped(scope)
        .api_keys()
        .verify(&plaintext, now_micros(&env))
        .await
        .expect("verify")
        .expect("a service-account key verifies");
    assert_eq!(resolved.owner, ApiKeyOwner::ServiceAccount(principal));

    // Can the principal actually vanish under a live key? No: migration 0123's
    // `FOREIGN KEY (service_account_id) REFERENCES service_accounts (id)` has no ON DELETE, so
    // it RESTRICTS. That is worth pinning, because it means `verify`'s presence check is
    // unreachable while a key exists rather than a live defence.
    //
    // The first version of this test deleted the KEY row and then the principal, and asserted
    // the key no longer verified. It did not verify because it had been deleted. The assertion
    // was true and measured nothing.
    let refused = sqlx::query("DELETE FROM service_accounts WHERE id = $1")
        .bind(principal.to_string())
        .execute(db.owner_pool())
        .await;
    assert!(
        refused.is_err(),
        "the foreign key must REFUSE removing a principal that still owns keys. If this ever \
         succeeds, `verify`'s service-account presence check becomes load-bearing and needs a \
         test that actually reaches it"
    );
    assert!(
        db.store()
            .scoped(scope)
            .api_keys()
            .verify(&plaintext, now_micros(&env))
            .await
            .expect("verify")
            .is_some(),
        "the refused delete must leave the key working"
    );
}

/// A retried create under the SAME idempotency key mints ONE credential, not two.
///
/// The parameter exists for this and nothing else. Without the replay row, a client whose
/// request times out and retries ends up holding one key while a SECOND, equally valid key
/// exists that it never saw and cannot revoke, discoverable only by an operator reading a
/// listing. That is a live credential nobody is tracking.
///
/// The replay row lands in the same transaction as the key, so the two cannot disagree about
/// whether the request already happened.
#[tokio::test]
async fn a_retried_create_under_one_idempotency_key_mints_exactly_one_key() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let user = seed_user(&db, &env, scope, "retry@example.test").await;
    let owner = ApiKeyOwner::User(user);

    // TWO DIFFERENT minted keys under one idempotency key, which is what a retry actually
    // looks like: the handler mints fresh material on each attempt and only the replay row
    // knows the request already happened.
    //
    // The first version of this test reused ONE minted key, so the second insert failed on
    // the digest primary key and the test passed with the idempotency write deleted. It was
    // measuring the primary key, not the property it claimed.
    let mut outcomes = Vec::new();
    for _ in 0..2 {
        let minted = mint_api_key(&env, &scope, ApiKeyKindTag::PersonalAccessToken);
        outcomes.push(
            db.control_store()
                .scoped(scope)
                .acting(db.test_actor(&env), CorrelationId::generate(&env))
                .api_keys()
                .create(
                    &env,
                    NewApiKey {
                        id: &minted.id,
                        key_digest: &minted.digest,
                        owner: &owner,
                        display_name: "retried",
                        expires_at_unix_micros: None,
                    },
                    now_micros(&env),
                    Some(ironauth_store::IdempotencyWrite {
                        credential_ref: "cred-99",
                        key: "retry-key",
                        request_fingerprint: "fp-99",
                        response_status: 200,
                        response_body: "{}",
                    }),
                )
                .await,
        );
    }
    assert!(outcomes[0].is_ok(), "the first create succeeds");
    assert!(
        outcomes[1].is_err(),
        "the second create under the same idempotency key must be refused at the store, \
         so the handler replays instead of minting again"
    );

    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM api_keys WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("count keys");
    assert_eq!(count, 1, "a retried create minted a SECOND live credential");
}

/// Revoking an API key emits `api_key.revoked` ONCE, and a retried revoke emits nothing
/// further (issue #108).
///
/// The idempotence is the substance. `revoke` is idempotent by design -- revoking an
/// already-revoked key changes nothing and writes no second audit row -- and the event has to
/// inherit that, or a receiver counting revocations sees two for one credential because a
/// client retried a request it never learned the outcome of.
#[tokio::test]
async fn revoking_an_api_key_emits_once_and_a_retry_emits_nothing() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let user = seed_user(&db, &env, scope, "pat-owner").await;
    let owner = ApiKeyOwner::User(user);
    let minted = mint_api_key(&env, &scope, ApiKeyKindTag::PersonalAccessToken);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .api_keys()
        .create(
            &env,
            NewApiKey {
                id: &minted.id,
                key_digest: &minted.digest,
                owner: &owner,
                display_name: "ci token",
                expires_at_unix_micros: None,
            },
            now_micros(&env),
            None,
        )
        .await
        .expect("create key");

    let envelope = ironauth_store::event_catalog::envelope(
        "evt_api_key_revoked",
        "api_key.revoked",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        1,
        &serde_json::json!({ "api_key_id": minted.id.to_string() }),
    )
    .expect("api_key.revoked is registered");
    let domain_event = ironauth_store::DomainEvent {
        id: "evt_api_key_revoked",
        subject: &minted.id.to_string(),
        envelope: &envelope,
    };

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .api_keys()
        .revoke_with_event(&env, &minted.id, now_micros(&env), Some(&domain_event))
        .await
        .expect("revoke");

    let events = queued_events(&db, scope).await;
    assert_eq!(events.len(), 1, "the revocation enqueues exactly one event");
    assert_eq!(events[0]["type"], "api_key.revoked");
    assert_eq!(events[0]["payload"]["api_key_id"], minted.id.to_string());
    ironauth_store::event_catalog::validate_event(&events[0])
        .expect("the envelope validates against the registry the fan-out enforces");

    // The RETRY. Same key, same call, and the store's early return must keep it silent.
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .api_keys()
        .revoke_with_event(&env, &minted.id, now_micros(&env), Some(&domain_event))
        .await
        .expect("revoke again");

    assert_eq!(
        queued_events(&db, scope).await.len(),
        0,
        "a retried revoke must emit nothing: the first one already drained, and a second \
         would make a receiver count two revocations for one credential"
    );
}

/// Every webhook-event envelope queued in `scope`.
async fn queued_events(db: &TestDatabase, scope: Scope) -> Vec<serde_json::Value> {
    use std::time::Duration;

    db.store()
        .scoped(scope)
        .outbox()
        .claim(
            &ironauth_env::Env::system(),
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
