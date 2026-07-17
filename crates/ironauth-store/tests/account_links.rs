// SPDX-License-Identifier: MIT OR Apache-2.0

//! Guarded account linking at the store layer (issue #78, PR 1), against a real database.
//!
//! These pin the storage-side guarantees the linking subsystem depends on, all with the
//! callback and the self-service API still UNWIRED (PR 1 is inert):
//!
//! - create / resolve / list round-trips, with the raw federated identifier landing only
//!   as a keyed blind index and a sealed ciphertext, and the immutable `email_verified`
//!   trust snapshot preserved verbatim;
//! - the STRUCTURAL anti-takeover invariant: a federated identity resolves to AT MOST one
//!   local user in a scope (a second local user claiming the same (connector, issuer, sub)
//!   is a conflict, never a silent re-home);
//! - the cross-source last-usable-method guard: unlinking (or removing a password) that
//!   would strand an account with NO usable authentication method is refused, and a
//!   surviving federated link counts as a usable method everywhere;
//! - scope isolation and the uniform IDOR not-found for a foreign or absent link.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    AccountLinkId, AccountLinkMethod, ActorRef, CorrelationId, HumanId, NewAccountLink,
    PasswordRemovalOutcome, Scope, StoreError, UnlinkOutcome, UserId,
};

/// A well-formed Argon2id verifier used where a real password hash is needed.
const REAL_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2g";

async fn register_password_user(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    handle: &str,
) -> UserId {
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .users()
        .register(env, handle, REAL_HASH)
        .await
        .expect("register password user")
}

/// Register a passkey-only (passwordless) account with NO passkey and NO credential, so a
/// single account link can be its sole usable authentication method.
async fn register_passwordless(db: &TestDatabase, env: &Env, scope: Scope, handle: &str) -> UserId {
    let id = UserId::generate(env, &scope);
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .users()
        .register_passwordless(env, &id, handle)
        .await
        .expect("register passwordless user");
    id
}

/// Create an account link for `subject` and return its fresh `alk_` id.
#[allow(clippy::too_many_arguments)] // a linear test helper; each field maps to a link column
async fn create_link(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    subject: &UserId,
    connector_id: &str,
    external_id: &str,
    email_verified: bool,
    method: AccountLinkMethod,
) -> AccountLinkId {
    let id = AccountLinkId::generate(env, &scope);
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .account_links()
        .create(
            env,
            &id,
            NewAccountLink {
                user_id: subject,
                connector_id,
                external_id,
                email_verified,
                link_method: method,
            },
        )
        .await
        .expect("create account link");
    id
}

#[tokio::test]
async fn create_resolve_and_list_round_trip_with_the_trust_snapshot_preserved() {
    let env = Env::system();
    let db = TestDatabase::start().await;
    let scope = db.seed_scope(&env).await;
    let subject = register_password_user(&db, &env, scope, "linker@example.test").await;

    let link_id = create_link(
        &db,
        &env,
        scope,
        &subject,
        "cnr_google",
        "federated:google:sub-123",
        true,
        AccountLinkMethod::AutoVerified,
    )
    .await;

    // Resolve by (connector, federated composite) finds the link and its owning user.
    let resolved = db
        .store()
        .scoped(scope)
        .account_links()
        .resolve("cnr_google", "federated:google:sub-123")
        .await
        .expect("resolve")
        .expect("the link resolves");
    assert_eq!(resolved.id, link_id);
    assert_eq!(resolved.user_id, subject.to_string());
    assert_eq!(resolved.connector_id, "cnr_google");
    assert!(
        resolved.email_verified,
        "the immutable trust snapshot is preserved verbatim"
    );
    assert_eq!(resolved.link_method, AccountLinkMethod::AutoVerified);

    // A wrong connector or a wrong federated composite resolves to nothing.
    assert!(
        db.store()
            .scoped(scope)
            .account_links()
            .resolve("cnr_apple", "federated:google:sub-123")
            .await
            .expect("resolve wrong connector")
            .is_none()
    );
    assert!(
        db.store()
            .scoped(scope)
            .account_links()
            .resolve("cnr_google", "federated:google:other")
            .await
            .expect("resolve wrong external id")
            .is_none()
    );

    // The user's list carries exactly the one link.
    let listed = db
        .store()
        .scoped(scope)
        .account_links()
        .list_for_user(&subject)
        .await
        .expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, link_id);
}

#[tokio::test]
async fn a_database_dump_of_account_links_carries_no_plaintext_federated_identifier() {
    let env = Env::system();
    let db = TestDatabase::start().await;
    let scope = db.seed_scope(&env).await;
    let subject = register_password_user(&db, &env, scope, "sealed@example.test").await;
    let secret_external = "federated:google:super-secret-subject";
    create_link(
        &db,
        &env,
        scope,
        &subject,
        "cnr_google",
        secret_external,
        true,
        AccountLinkMethod::Manual,
    )
    .await;

    // The raw federated identifier never lands in plaintext: neither the blind index nor
    // the sealed ciphertext bytes contain it.
    let (bidx, sealed): (Vec<u8>, Vec<u8>) =
        sqlx::query_as("SELECT external_id_bidx, external_id_sealed FROM account_links")
            .fetch_one(db.owner_pool())
            .await
            .expect("read raw columns");
    let needle = secret_external.as_bytes();
    assert!(
        !bidx.windows(needle.len()).any(|w| w == needle),
        "the blind index must not contain the plaintext federated identifier"
    );
    assert!(
        !sealed.windows(needle.len()).any(|w| w == needle),
        "the sealed ciphertext must not contain the plaintext federated identifier"
    );
}

#[tokio::test]
async fn a_federated_identity_links_to_at_most_one_local_user() {
    let env = Env::system();
    let db = TestDatabase::start().await;
    let scope = db.seed_scope(&env).await;
    let victim = register_password_user(&db, &env, scope, "victim@example.test").await;
    let attacker = register_password_user(&db, &env, scope, "attacker@example.test").await;

    // The victim's federated identity is linked to the victim.
    create_link(
        &db,
        &env,
        scope,
        &victim,
        "cnr_google",
        "federated:google:victim",
        true,
        AccountLinkMethod::Manual,
    )
    .await;

    // The attacker cannot claim the SAME (connector, federated identity): the per-scope
    // UNIQUE constraint is the structural anti-takeover invariant (a conflict, never a
    // silent re-home into the attacker's account).
    let conflict = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .account_links()
        .create(
            &env,
            &AccountLinkId::generate(&env, &scope),
            NewAccountLink {
                user_id: &attacker,
                connector_id: "cnr_google",
                external_id: "federated:google:victim",
                email_verified: true,
                link_method: AccountLinkMethod::Manual,
            },
        )
        .await;
    assert!(
        matches!(conflict, Err(StoreError::Conflict)),
        "a federated identity may resolve to at most one local user, got: {conflict:?}"
    );

    // The identity still resolves to the victim, unchanged.
    let resolved = db
        .store()
        .scoped(scope)
        .account_links()
        .resolve("cnr_google", "federated:google:victim")
        .await
        .expect("resolve")
        .expect("still linked");
    assert_eq!(resolved.user_id, victim.to_string());
}

#[tokio::test]
async fn unlinking_the_sole_usable_method_is_blocked_and_the_link_survives() {
    let env = Env::system();
    let db = TestDatabase::start().await;
    let scope = db.seed_scope(&env).await;
    // A passwordless account with NO passkey and NO credential: a single link is its sole
    // usable authentication method.
    let subject = register_passwordless(&db, &env, scope, "sole-link@example.test").await;
    let link_id = create_link(
        &db,
        &env,
        scope,
        &subject,
        "cnr_google",
        "federated:google:sole",
        true,
        AccountLinkMethod::Manual,
    )
    .await;

    let acting = || {
        db.store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
    };

    // Unlinking the sole method is REFUSED (the Zitadel #6081 anti-bricking guard).
    let blocked = acting()
        .account_links()
        .unlink(&env, &subject, &link_id, "step_up_max_age_secs=300")
        .await
        .expect("unlink");
    assert_eq!(blocked, UnlinkOutcome::BlockedLastMethod);
    // The link survived the blocked unlink.
    assert!(
        db.store()
            .scoped(scope)
            .account_links()
            .resolve("cnr_google", "federated:google:sole")
            .await
            .expect("resolve")
            .is_some(),
        "the sole-method link must survive the blocked unlink"
    );

    // Add a SECOND link: now the first is no longer the sole method, so unlinking it is
    // ALLOWED (a surviving link counts as a usable method).
    create_link(
        &db,
        &env,
        scope,
        &subject,
        "cnr_apple",
        "federated:apple:second",
        false,
        AccountLinkMethod::Manual,
    )
    .await;
    let removed = acting()
        .account_links()
        .unlink(&env, &subject, &link_id, "step_up_max_age_secs=300")
        .await
        .expect("unlink");
    assert_eq!(removed, UnlinkOutcome::Removed);
    assert!(
        db.store()
            .scoped(scope)
            .account_links()
            .resolve("cnr_google", "federated:google:sole")
            .await
            .expect("resolve")
            .is_none(),
        "the unlinked link is gone"
    );
}

#[tokio::test]
async fn unlinking_a_link_is_allowed_when_a_password_survives() {
    let env = Env::system();
    let db = TestDatabase::start().await;
    let scope = db.seed_scope(&env).await;
    // A password account with one linked identity: the password is a surviving method, so
    // unlinking the link never strands the account.
    let subject = register_password_user(&db, &env, scope, "pw-and-link@example.test").await;
    let link_id = create_link(
        &db,
        &env,
        scope,
        &subject,
        "cnr_google",
        "federated:google:pw",
        true,
        AccountLinkMethod::AutoVerified,
    )
    .await;

    let removed = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .account_links()
        .unlink(&env, &subject, &link_id, "step_up_max_age_secs=300")
        .await
        .expect("unlink");
    assert_eq!(
        removed,
        UnlinkOutcome::Removed,
        "the password survives, so unlinking is allowed"
    );
}

#[tokio::test]
async fn removing_the_password_counts_a_surviving_link_as_a_usable_method() {
    let env = Env::system();
    let db = TestDatabase::start().await;
    let scope = db.seed_scope(&env).await;

    let acting = |subject_scope: Scope| {
        db.store()
            .scoped(subject_scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
    };

    // A password user with NO other method: removing the password is BLOCKED.
    let lonely = register_password_user(&db, &env, scope, "lonely@example.test").await;
    let blocked = acting(scope)
        .users()
        .remove_password(&env, &lonely, None, "step_up_max_age_secs=300")
        .await
        .expect("remove_password");
    assert_eq!(
        blocked,
        PasswordRemovalOutcome::BlockedLastCredential,
        "with no other method, password removal is blocked"
    );

    // A password user WITH a linked identity: the link is a surviving usable method (issue
    // #78's fourth source), so removing the password is ALLOWED.
    let linked = register_password_user(&db, &env, scope, "linked@example.test").await;
    create_link(
        &db,
        &env,
        scope,
        &linked,
        "cnr_google",
        "federated:google:pw-link",
        true,
        AccountLinkMethod::AutoVerified,
    )
    .await;
    let removed = acting(scope)
        .users()
        .remove_password(&env, &linked, None, "step_up_max_age_secs=300")
        .await
        .expect("remove_password");
    assert!(
        matches!(removed, PasswordRemovalOutcome::Removed(_)),
        "a surviving federated link counts as a usable method, so removal is allowed"
    );
}

#[tokio::test]
async fn unlinking_a_foreign_or_absent_link_is_the_uniform_not_found() {
    let env = Env::system();
    let db = TestDatabase::start().await;
    let scope = db.seed_scope(&env).await;
    let owner = register_password_user(&db, &env, scope, "owner@example.test").await;
    let other = register_password_user(&db, &env, scope, "other@example.test").await;
    let link_id = create_link(
        &db,
        &env,
        scope,
        &owner,
        "cnr_google",
        "federated:google:owned",
        true,
        AccountLinkMethod::Manual,
    )
    .await;

    // A different subject unlinking the owner's link finds no row: the uniform not-found,
    // never an oracle for a foreign link's existence, and never a cross-owner delete.
    let foreign = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .account_links()
        .unlink(&env, &other, &link_id, "step_up_max_age_secs=300")
        .await
        .expect("unlink");
    assert_eq!(foreign, UnlinkOutcome::NotFound);
    // The owner's link is untouched.
    assert!(
        db.store()
            .scoped(scope)
            .account_links()
            .resolve("cnr_google", "federated:google:owned")
            .await
            .expect("resolve")
            .is_some(),
        "a foreign unlink must not delete the owner's link"
    );

    // A link minted in ANOTHER scope parses as not-found here (scope isolation).
    let other_scope = db.seed_scope(&env).await;
    let cross = db
        .store()
        .scoped(other_scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .account_links()
        .unlink(&env, &owner, &link_id, "step_up_max_age_secs=300")
        .await
        .expect("unlink cross scope");
    assert_eq!(cross, UnlinkOutcome::NotFound);
}

/// A fresh actor for a spawned concurrency task (no `&TestDatabase` is in scope inside
/// the task closure to hand out one).
fn task_actor(env: &Env) -> ActorRef {
    ActorRef::human(HumanId::generate(env))
}

/// The permanent adversarial concurrency guard issue #78 mandates: two racing removals
/// of the LAST two usable methods must never BOTH pass the last-usable-method count and
/// leave the account with ZERO methods.
///
/// Before the per-user serialization lock this bricked 78 of 80 trials: each racer
/// writes a DISJOINT row (an `account_links` delete), and under READ COMMITTED each
/// non-locking `count(*)` reads the OTHER's still-committed link as a surviving method,
/// so both pass the guard and both commit (the Zitadel #6081 class). Taking the user
/// row `FOR UPDATE` first makes the racers mutually exclude on the same per-user key, so
/// exactly one wins and the loser re-reads the committed state and is refused.
#[tokio::test]
async fn two_concurrent_unlinks_of_the_last_two_links_never_brick_the_account() {
    let env = Env::system();
    let db = TestDatabase::start().await;
    let scope = db.seed_scope(&env).await;
    // A wider pool so the two racers run truly in parallel rather than serializing on a
    // single pooled connection (which would blunt the very race this test exists to catch).
    let store = db.app_store_with_pool(8).await;

    // Enough iterations to have caught the pre-fix 78/80 brick rate. The lock makes each
    // iteration deterministic (exactly one winner), so a single brick fails the suite.
    for i in 0..40 {
        // A passwordless account whose ONLY two usable methods are these two links.
        let subject =
            register_passwordless(&db, &env, scope, &format!("race-links-{i}@example.test")).await;
        let link_a = create_link(
            &db,
            &env,
            scope,
            &subject,
            "cnr_google",
            &format!("federated:google:a-{i}"),
            true,
            AccountLinkMethod::Manual,
        )
        .await;
        let link_b = create_link(
            &db,
            &env,
            scope,
            &subject,
            "cnr_apple",
            &format!("federated:apple:b-{i}"),
            false,
            AccountLinkMethod::Manual,
        )
        .await;

        let mut handles = Vec::new();
        for link_id in [link_a, link_b] {
            let store = store.clone();
            let env = env.clone();
            handles.push(tokio::spawn(async move {
                store
                    .scoped(scope)
                    .acting(task_actor(&env), CorrelationId::generate(&env))
                    .account_links()
                    .unlink(&env, &subject, &link_id, "step_up_max_age_secs=300")
                    .await
                    .expect("unlink")
            }));
        }

        let mut removed = 0_u32;
        let mut blocked = 0_u32;
        for handle in handles {
            match handle.await.expect("task joins") {
                UnlinkOutcome::Removed => removed += 1,
                UnlinkOutcome::BlockedLastMethod => blocked += 1,
                other @ UnlinkOutcome::NotFound => {
                    panic!("unexpected unlink outcome in the race: {other:?}")
                }
            }
        }
        assert_eq!(
            removed, 1,
            "exactly one racer removes a link (iteration {i})"
        );
        assert_eq!(
            blocked, 1,
            "the other racer is refused by the guard (iteration {i})"
        );

        // The account is never bricked: exactly one usable link survives.
        let surviving = db
            .store()
            .scoped(scope)
            .account_links()
            .list_for_user(&subject)
            .await
            .expect("list");
        assert_eq!(
            surviving.len(),
            1,
            "the account retains exactly one usable method (iteration {i})"
        );
    }
}

/// The same guard across DIFFERENT handlers taking the SAME per-user key: a password
/// removal racing an unlink of the account's last link. Both mutate DISJOINT rows (the
/// `users` password flip vs the `account_links` delete), so without the shared users-row
/// lock both could pass their own cross-source count and strand the account. The lock
/// serializes them on the user row, so exactly one of the two wins and the other is
/// refused, proving the two handlers take the same per-user key (a mix of keys would not
/// serialize them).
#[tokio::test]
async fn a_concurrent_password_removal_and_unlink_never_brick_the_account() {
    let env = Env::system();
    let db = TestDatabase::start().await;
    let scope = db.seed_scope(&env).await;
    let store = db.app_store_with_pool(8).await;

    for i in 0..40 {
        // Exactly two usable methods: a native password and one federated link.
        let subject =
            register_password_user(&db, &env, scope, &format!("race-pw-{i}@example.test")).await;
        let link_id = create_link(
            &db,
            &env,
            scope,
            &subject,
            "cnr_google",
            &format!("federated:google:pw-{i}"),
            true,
            AccountLinkMethod::AutoVerified,
        )
        .await;

        let unlink_task = {
            let store = store.clone();
            let env = env.clone();
            tokio::spawn(async move {
                store
                    .scoped(scope)
                    .acting(task_actor(&env), CorrelationId::generate(&env))
                    .account_links()
                    .unlink(&env, &subject, &link_id, "step_up_max_age_secs=300")
                    .await
                    .expect("unlink")
            })
        };
        let remove_pw_task = {
            let store = store.clone();
            let env = env.clone();
            tokio::spawn(async move {
                store
                    .scoped(scope)
                    .acting(task_actor(&env), CorrelationId::generate(&env))
                    .users()
                    .remove_password(&env, &subject, None, "step_up_max_age_secs=300")
                    .await
                    .expect("remove_password")
            })
        };

        let unlink_outcome = unlink_task.await.expect("unlink task joins");
        let remove_pw_outcome = remove_pw_task.await.expect("remove_password task joins");

        let unlink_removed = matches!(unlink_outcome, UnlinkOutcome::Removed);
        let pw_removed = matches!(remove_pw_outcome, PasswordRemovalOutcome::Removed(_));
        // Exactly ONE of the two racers removes a method; the other is refused, so the
        // account is never left with zero usable methods (iteration {i}).
        assert!(
            unlink_removed ^ pw_removed,
            "exactly one of (unlink, remove_password) wins the race (iteration {i}): \
             unlink={unlink_outcome:?} remove_password={remove_pw_outcome:?}"
        );
        if unlink_removed {
            assert_eq!(
                remove_pw_outcome,
                PasswordRemovalOutcome::BlockedLastCredential,
                "the password removal is the refused racer (iteration {i})"
            );
        } else {
            assert_eq!(
                unlink_outcome,
                UnlinkOutcome::BlockedLastMethod,
                "the unlink is the refused racer (iteration {i})"
            );
        }
    }
}
