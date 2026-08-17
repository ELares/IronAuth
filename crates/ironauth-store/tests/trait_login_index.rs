// SPDX-License-Identifier: MIT OR Apache-2.0

//! The blind index that lets an ANNOTATED trait value resolve a user (issue #624), over a
//! real database (`DATABASE_URL`).
//!
//! Traits are sealed, so `user` to `trait` is possible and `trait` to `user` is not. That is
//! why the recovery and verification halves of issue #53 criterion 2 shipped and the LOGIN
//! half did not: those run user-first. `user_trait_login_index` is the keyed-HMAC table that
//! makes the other direction answerable without a plaintext column, and this file pins the
//! four properties issue #624 says it must have.
//!
//! * An annotated value RESOLVES its holder, and an unannotated one resolves nobody. The
//!   second half is the one that keeps this from becoming a general search over sealed PII:
//!   if an unannotated field resolved, anyone who can call login could test for the presence
//!   of any trait value in the environment.
//! * Two users sharing an annotated value resolve to NEITHER, and the refusal is the same
//!   uniform `None` an unknown value gets. Picking one would be an account-takeover
//!   primitive.
//! * A field that stops being annotated stops resolving, and a field that STARTS being
//!   annotated does not silently lock anyone out: an un-backfilled user is simply not
//!   resolvable through that field yet, which is a miss and not a wrong answer.
//! * The index is maintained in the same transaction as the trait, so a value that was just
//!   changed resolves the new holder and no longer resolves through the old value.
//!
//! What is NOT here, deliberately: the HTTP login wiring and the backfill JOB. Both are the
//! next PRs on #624. This file is the persistence layer those build on, and pinning it first
//! is what makes the later wiring a wiring change rather than a crypto change.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, NewAdminUser, NewUserTraits, Scope, TraitWriteVisibility, UserId, UserState,
};
use serde_json::json;

const PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaGhhc2hoYXNo";
const NOW_MICROS: i64 = 1_000_000;

/// A schema whose `handle` is annotated as a login identifier and whose `nickname` is not.
///
/// The pair is the point. One annotated and one unannotated field of the SAME type, holding
/// the SAME value in the tests below, is what separates "the index resolves annotated
/// fields" from "the index resolves whatever it was handed".
fn schema_with_annotated_handle() -> String {
    json!({
        "type": "object",
        "properties": {
            "handle": {"type": "string", "x-ironauth": {"identifier": true}},
            "nickname": {"type": "string"}
        }
    })
    .to_string()
}

/// The same schema with the annotation MOVED to `nickname`, for the annotation-change tests.
fn schema_with_annotated_nickname() -> String {
    json!({
        "type": "object",
        "properties": {
            "handle": {"type": "string"},
            "nickname": {"type": "string", "x-ironauth": {"identifier": true}}
        }
    })
    .to_string()
}

async fn activate(db: &TestDatabase, env: &Env, scope: Scope, schema_json: &str) -> i32 {
    let repo = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env));
    let version = repo
        .trait_schemas()
        .create_version(env, schema_json, NOW_MICROS)
        .await
        .expect("create schema version")
        .1;
    repo.trait_schemas()
        .activate_version(env, version)
        .await
        .expect("activate schema version");
    version
}

/// Create a user, optionally carrying traits at creation time.
async fn create_user(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    identifier: &str,
    traits_json: Option<&str>,
) -> UserId {
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
                external_id: None,
                state: UserState::Active,
                foreign_password_hash: None,
                foreign_password_algo: None,
                traits: traits_json.map(|traits_json| NewUserTraits {
                    traits_json,
                    schema_version: None,
                    visibility: TraitWriteVisibility::Admin,
                }),
            },
            NOW_MICROS,
            None,
        )
        .await
        .expect("create user")
}

async fn set_traits(db: &TestDatabase, env: &Env, scope: Scope, id: &UserId, traits: &str) {
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .users()
        .set_traits(env, id, traits)
        .await
        .expect("set traits");
}

/// Resolve through the annotated-trait index.
async fn resolve(
    db: &TestDatabase,
    scope: Scope,
    field: &str,
    value: &str,
) -> Option<ironauth_store::UserId> {
    db.store()
        .scoped(scope)
        .users()
        .by_annotated_trait(field, value)
        .await
        .expect("resolve by annotated trait")
        .map(|record| record.id)
}

/// An ANNOTATED trait value resolves its holder; an UNANNOTATED one resolves nobody.
///
/// Both fields hold the same string, so the difference in outcome is the annotation and
/// nothing else. Without the negative half this test would pass for an index that indexed
/// every trait field, which is a searchable index over arbitrary sealed PII reachable by
/// anyone who can submit a login.
#[tokio::test]
async fn an_annotated_value_resolves_and_an_unannotated_one_never_does() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x91);
    let scope = db.seed_scope(&env).await;
    activate(&db, &env, scope, &schema_with_annotated_handle()).await;

    let user = create_user(&db, &env, scope, "u1@x.test", None).await;
    set_traits(
        &db,
        &env,
        scope,
        &user,
        &json!({"handle": "shared-value", "nickname": "shared-value"}).to_string(),
    )
    .await;

    assert_eq!(
        resolve(&db, scope, "handle", "shared-value").await,
        Some(user),
        "the annotated field must resolve its holder, or `login_identifiers` drives nothing"
    );
    assert_eq!(
        resolve(&db, scope, "nickname", "shared-value").await,
        None,
        "an UNANNOTATED field resolved a user, which makes this index a general search over \
         sealed trait values for anyone who can call the login endpoint"
    );
}

/// Resolution is canonicalizing and scope-fenced.
///
/// Case and surrounding whitespace must not decide whether a login succeeds; a different
/// ENVIRONMENT must, and the same value in a sibling scope resolves nobody even though the
/// underlying string is identical.
#[tokio::test]
async fn resolution_canonicalizes_the_value_and_never_crosses_a_scope() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x92);
    let scope = db.seed_scope(&env).await;
    let other = db.seed_scope(&env).await;
    for target in [scope, other] {
        activate(&db, &env, target, &schema_with_annotated_handle()).await;
    }

    let user = create_user(&db, &env, scope, "u1@x.test", None).await;
    set_traits(
        &db,
        &env,
        scope,
        &user,
        &json!({"handle": "Ada.Lovelace"}).to_string(),
    )
    .await;

    for spelling in [
        "Ada.Lovelace",
        "ada.lovelace",
        "  ADA.LOVELACE  ",
        "Ada. Lovelace",
    ] {
        assert_eq!(
            resolve(&db, scope, "handle", spelling).await,
            Some(user),
            "`{spelling}` must resolve the same user: whether a login succeeds cannot depend \
             on case or whitespace, or the same person is admitted through one spelling and \
             refused through another"
        );
    }
    assert_eq!(
        resolve(&db, other, "handle", "Ada.Lovelace").await,
        None,
        "the identical value resolved across a scope boundary, so the index tag is not \
         bound to the tenant and environment"
    );
}

/// TWO users sharing an annotated value resolve to NEITHER of them.
///
/// This is issue #624 point 4 and the reason the lookup index is deliberately not unique.
/// Uniqueness would make the SECOND user's trait write fail, reporting an ambiguous login as
/// a failed profile update somewhere else; here the write succeeds and the READ refuses.
///
/// The refusal is asserted to be the SAME uniform `None` an unknown value gets, because a
/// distinguishable ambiguity answer would tell a prober that some other account holds the
/// value they just tried.
#[tokio::test]
async fn two_users_sharing_a_value_resolve_to_neither_and_look_like_an_unknown_value() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x93);
    let scope = db.seed_scope(&env).await;
    activate(&db, &env, scope, &schema_with_annotated_handle()).await;

    let alice = create_user(&db, &env, scope, "alice@x.test", None).await;
    let bob = create_user(&db, &env, scope, "bob@x.test", None).await;
    let shared = json!({"handle": "duplicate"}).to_string();

    set_traits(&db, &env, scope, &alice, &shared).await;
    assert_eq!(
        resolve(&db, scope, "handle", "duplicate").await,
        Some(alice),
        "one holder resolves, so the ambiguity below is the SECOND write's doing"
    );

    // The second write SUCCEEDS. A unique index would fail it here, which is the design this
    // deliberately does not have.
    set_traits(&db, &env, scope, &bob, &shared).await;

    assert_eq!(
        resolve(&db, scope, "handle", "duplicate").await,
        None,
        "an ambiguous value resolved somebody; whichever one it picked, planting that value \
         is then a way to be handed another account's login"
    );
    assert_eq!(
        resolve(&db, scope, "handle", "never-used-by-anyone").await,
        None,
        "the ambiguous refusal must be indistinguishable from an unknown value, or the \
         difference is an oracle for which values other accounts hold"
    );

    // And it recovers: once one of them stops holding the value, the other resolves again.
    set_traits(
        &db,
        &env,
        scope,
        &bob,
        &json!({"handle": "bob-only"}).to_string(),
    )
    .await;
    assert_eq!(
        resolve(&db, scope, "handle", "duplicate").await,
        Some(alice),
        "ambiguity must be a property of the CURRENT rows, not a latch: clearing the \
         collision has to restore the remaining holder"
    );
    assert_eq!(
        resolve(&db, scope, "handle", "bob-only").await,
        Some(bob),
        "the rewritten value resolves its new holder"
    );
}

/// Changing an annotated value stops the OLD value resolving.
///
/// The index is rewritten in the same transaction as the trait, so there is no window in
/// which both spellings work. A stale row surviving here would mean an address a user
/// deliberately removed still logs them in.
#[tokio::test]
async fn changing_the_value_stops_the_old_one_resolving_in_the_same_transaction() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x94);
    let scope = db.seed_scope(&env).await;
    activate(&db, &env, scope, &schema_with_annotated_handle()).await;

    let user = create_user(&db, &env, scope, "u1@x.test", None).await;
    set_traits(
        &db,
        &env,
        scope,
        &user,
        &json!({"handle": "before"}).to_string(),
    )
    .await;
    assert_eq!(resolve(&db, scope, "handle", "before").await, Some(user));

    set_traits(
        &db,
        &env,
        scope,
        &user,
        &json!({"handle": "after"}).to_string(),
    )
    .await;
    assert_eq!(
        resolve(&db, scope, "handle", "before").await,
        None,
        "the OLD value still resolves, so a handle a user removed still logs them in"
    );
    assert_eq!(resolve(&db, scope, "handle", "after").await, Some(user));
}

/// An annotation CHANGE does not silently lock anyone out, in both directions.
///
/// Un-annotating a field must stop it resolving on the next trait write; that is a removal
/// of a capability and taking effect immediately is the safe direction. Newly annotating a
/// field leaves existing users unresolvable through it until they write or a backfill runs,
/// which is a MISS rather than a wrong answer: nobody else resolves in their place, and
/// their existing login route is untouched.
///
/// The second half is what issue #624 point 3 is about, and the assertion that matters is
/// the one about the OTHER user: an un-backfilled index must never resolve the wrong person.
#[tokio::test]
async fn an_annotation_change_never_resolves_the_wrong_user() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x95);
    let scope = db.seed_scope(&env).await;
    activate(&db, &env, scope, &schema_with_annotated_handle()).await;

    let user = create_user(&db, &env, scope, "u1@x.test", None).await;
    let other = create_user(&db, &env, scope, "u2@x.test", None).await;
    set_traits(
        &db,
        &env,
        scope,
        &user,
        &json!({"handle": "hh", "nickname": "nn"}).to_string(),
    )
    .await;
    set_traits(
        &db,
        &env,
        scope,
        &other,
        &json!({"handle": "other-hh", "nickname": "other-nn"}).to_string(),
    )
    .await;
    assert_eq!(resolve(&db, scope, "handle", "hh").await, Some(user));

    // Move the annotation from `handle` to `nickname`.
    activate(&db, &env, scope, &schema_with_annotated_nickname()).await;

    // Nobody's rows have been rewritten yet, so `nickname` does not resolve. That is the
    // un-backfilled state, and the requirement is that it is a MISS.
    assert_eq!(
        resolve(&db, scope, "nickname", "nn").await,
        None,
        "an un-backfilled annotation must not resolve; it has no rows to resolve FROM"
    );
    assert_eq!(
        resolve(&db, scope, "nickname", "other-nn").await,
        None,
        "and it must not resolve anyone ELSE either, which is the failure that would matter"
    );

    // One trait write under the new schema brings that user's rows in line: `nickname` now
    // resolves them and the un-annotated `handle` stops.
    set_traits(
        &db,
        &env,
        scope,
        &user,
        &json!({"handle": "hh", "nickname": "nn"}).to_string(),
    )
    .await;
    assert_eq!(
        resolve(&db, scope, "nickname", "nn").await,
        Some(user),
        "a write under the new annotations must index the newly annotated field"
    );
    assert_eq!(
        resolve(&db, scope, "handle", "hh").await,
        None,
        "the UN-annotated field must stop resolving; leaving it live would keep a login \
         route open that the schema no longer declares"
    );

    // The user who has not written since the change keeps neither route, and crucially
    // resolves as nobody rather than as somebody.
    assert_eq!(resolve(&db, scope, "nickname", "other-nn").await, None);
    assert_eq!(
        resolve(&db, scope, "handle", "other-hh").await,
        Some(other),
        "a user who has not written since the change still resolves through the route their \
         OWN rows were written under; the change is not retroactive and must not orphan them \
         before the backfill runs"
    );
}

/// A soft-deleted holder resolves as nobody, exactly as `by_identifier` treats a tombstone.
#[tokio::test]
async fn a_soft_deleted_holder_resolves_as_nobody() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x96);
    let scope = db.seed_scope(&env).await;
    activate(&db, &env, scope, &schema_with_annotated_handle()).await;

    let user = create_user(&db, &env, scope, "u1@x.test", None).await;
    set_traits(
        &db,
        &env,
        scope,
        &user,
        &json!({"handle": "gone-soon"}).to_string(),
    )
    .await;
    assert_eq!(resolve(&db, scope, "handle", "gone-soon").await, Some(user));

    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .users()
        // Soft delete (`hard_kill = false`): the tombstone is exactly the state the lookup
        // must read as absent.
        .delete(&env, &user, false, None, None)
        .await
        .expect("soft-delete the user");

    assert_eq!(
        resolve(&db, scope, "handle", "gone-soon").await,
        None,
        "a deleted user must not authenticate through a trait when they cannot through an \
         identifier"
    );
}

/// An EMPTY or whitespace-only annotated value indexes nothing.
///
/// Every user who leaves the field blank would otherwise share one canonical value, be
/// mutually ambiguous, and refuse each other. Worse, the first such user would resolve for a
/// submitted empty value until the second appeared.
#[tokio::test]
async fn a_blank_annotated_value_indexes_nobody() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x97);
    let scope = db.seed_scope(&env).await;
    activate(&db, &env, scope, &schema_with_annotated_handle()).await;

    let user = create_user(&db, &env, scope, "u1@x.test", None).await;
    for blank in ["", "   "] {
        set_traits(
            &db,
            &env,
            scope,
            &user,
            &json!({ "handle": blank }).to_string(),
        )
        .await;
        assert_eq!(
            resolve(&db, scope, "handle", blank).await,
            None,
            "a blank value resolved a user; every user who leaves the field empty shares \
             that value, so it is an ambiguity magnet rather than an identifier"
        );
    }
}

/// Traits supplied at CREATE time are indexed, not only traits set afterwards.
///
/// The create seam is a separate code path from `set_traits`, and an index maintained on one
/// but not the other is the shape where an imported or admin-created user cannot log in with
/// the value they were created with until something else happens to touch them.
#[tokio::test]
async fn traits_supplied_at_create_time_are_indexed_too() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x98);
    let scope = db.seed_scope(&env).await;
    activate(&db, &env, scope, &schema_with_annotated_handle()).await;

    let user = create_user(
        &db,
        &env,
        scope,
        "created@x.test",
        Some(&json!({"handle": "at-create"}).to_string()),
    )
    .await;

    assert_eq!(
        resolve(&db, scope, "handle", "at-create").await,
        Some(user),
        "a user created WITH traits must resolve through them; otherwise an imported \
         identity cannot log in until an unrelated write happens to rebuild its index"
    );
}

/// The stored TAG is separated by field, by scope, and from the `users.identifier_bidx`
/// column, asserted on the bytes themselves.
///
/// This test exists because a mutation sweep proved the others could not see any of it.
/// Removing the field binding, the scope binding, or the distinct AAD label changed NO
/// lookup result, and for a good reason: the lookup already filters on `field`, on
/// `tenant_id` and on `environment_id`, and it reads only its own table. So no query can
/// reach a colliding tag however the tag was derived.
///
/// What the bindings actually buy is that the tag carries no cross-context meaning at rest.
/// Equal tags in a database dump would tell whoever holds it that two users share a value
/// across two fields, across two environments, or between a trait and a login handle, which
/// is exactly the correlation sealing the column was meant to deny. That is only observable
/// by reading the stored bytes, so this reads them.
#[tokio::test]
async fn the_tag_is_separated_by_field_scope_and_column() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x99);
    let scope = db.seed_scope(&env).await;
    let other = db.seed_scope(&env).await;

    // A schema annotating BOTH fields, so both produce a row for the same value.
    let both = json!({
        "type": "object",
        "properties": {
            "handle": {"type": "string", "x-ironauth": {"identifier": true}},
            "nickname": {"type": "string", "x-ironauth": {"identifier": true}}
        }
    })
    .to_string();
    for target in [scope, other] {
        activate(&db, &env, target, &both).await;
    }

    // The SAME value everywhere: in two annotated fields, in two scopes, and as the login
    // identifier of the user in the first scope.
    let value = "collide@x.test";
    let here = create_user(&db, &env, scope, value, None).await;
    let there = create_user(&db, &env, other, value, None).await;
    let doc = json!({"handle": value, "nickname": value}).to_string();
    set_traits(&db, &env, scope, &here, &doc).await;
    set_traits(&db, &env, other, &there, &doc).await;

    let tag = |target: Scope, field: &'static str| {
        let pool = db.owner_pool().clone();
        async move {
            sqlx::query_scalar::<_, String>(
                "SELECT blind_index FROM user_trait_login_index \
                 WHERE tenant_id = $1 AND environment_id = $2 AND field = $3",
            )
            .bind(target.tenant().to_string())
            .bind(target.environment().to_string())
            .bind(field)
            .fetch_one(&pool)
            .await
            .expect("the fixture wrote a row")
        }
    };

    let handle_here = tag(scope, "handle").await;
    let nickname_here = tag(scope, "nickname").await;
    let handle_other_scope = tag(other, "handle").await;

    assert_ne!(
        handle_here, nickname_here,
        "the same value under two annotated FIELDS produced the same tag, so a dump reveals \
         that one user's `handle` and `nickname` are equal without revealing either"
    );
    assert_ne!(
        handle_here, handle_other_scope,
        "the same value in two SCOPES produced the same tag, so a dump correlates accounts \
         across environments that share nothing else"
    );

    // And against the login-handle index, which is a different column entirely.
    let identifier_tag: String = sqlx::query_scalar(
        "SELECT encode(identifier_bidx, 'hex') FROM users \
         WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
    )
    .bind(here.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("the user row exists");
    assert_ne!(
        handle_here, identifier_tag,
        "the trait tag equals the `users.identifier_bidx` tag for the same string, so \
         whoever can write a trait can confirm whether a given login handle exists by \
         comparing the two columns"
    );
}

/// Create and drive a `BackfillLoginIndex` job to completion, returning the final job.
async fn backfill(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    to_version: i32,
    batch_limit: i64,
) -> ironauth_store::TraitMigrationJob {
    let repo = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env));
    let job_id = repo
        .trait_migration_jobs()
        .create(
            env,
            ironauth_store::NewTraitMigrationJob {
                kind: ironauth_store::TraitJobKind::BackfillLoginIndex,
                from_version: to_version,
                to_version,
                transform_json: None,
            },
            NOW_MICROS,
            ironauth_store::TraitMigrationStart {
                first_batch_payload: &json!({}),
                idempotency: None,
            },
        )
        .await
        .expect("create the backfill job");

    // Drive to a terminal status. Bounded so a job that never terminates fails the test
    // rather than hanging it.
    let mut job = repo
        .trait_migration_jobs()
        .advance(env, &job_id, batch_limit)
        .await
        .expect("advance the backfill");
    for _ in 0..50 {
        if job.status.is_terminal() {
            break;
        }
        job = repo
            .trait_migration_jobs()
            .advance(env, &job_id, batch_limit)
            .await
            .expect("advance the backfill");
    }
    assert!(
        job.status.is_terminal(),
        "the backfill did not terminate within the bound: {:?}",
        job.status
    );
    job
}

/// Issue #624 point 2: a backfill makes a NEWLY annotated field resolve users who have not
/// written traits since the annotation changed.
///
/// This is the whole reason the job exists. The index is maintained on every trait write, so
/// the population it cannot reach is the people who never write again, and without a sweep
/// an operator who annotates a field publishes a login route that works for nobody who
/// already existed.
#[tokio::test]
async fn a_backfill_makes_a_newly_annotated_field_resolve_existing_users() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x9a);
    let scope = db.seed_scope(&env).await;
    activate(&db, &env, scope, &schema_with_annotated_handle()).await;

    let user = create_user(&db, &env, scope, "u1@x.test", None).await;
    let other = create_user(&db, &env, scope, "u2@x.test", None).await;
    set_traits(
        &db,
        &env,
        scope,
        &user,
        &json!({"handle": "hh", "nickname": "nn"}).to_string(),
    )
    .await;
    set_traits(
        &db,
        &env,
        scope,
        &other,
        &json!({"handle": "other-hh", "nickname": "other-nn"}).to_string(),
    )
    .await;

    // Move the annotation. Neither user writes again.
    let v2 = activate(&db, &env, scope, &schema_with_annotated_nickname()).await;
    assert_eq!(
        resolve(&db, scope, "nickname", "nn").await,
        None,
        "before the backfill the newly annotated field resolves nobody"
    );

    let job = backfill(&db, &env, scope, v2, 100).await;
    assert_eq!(
        job.status,
        ironauth_store::TraitJobStatus::Completed,
        "the backfill must complete: it validates nothing, so there is nothing to fail on"
    );
    assert_eq!(job.processed_count, 2, "both identities were swept");

    assert_eq!(
        resolve(&db, scope, "nickname", "nn").await,
        Some(user),
        "after the backfill the newly annotated field resolves its holder"
    );
    assert_eq!(
        resolve(&db, scope, "nickname", "other-nn").await,
        Some(other),
        "and it resolves the user who never wrote either, which is the population the \
         backfill exists for"
    );
    assert_eq!(
        resolve(&db, scope, "handle", "hh").await,
        None,
        "the UN-annotated field must stop resolving after the sweep, or a login route the \
         schema no longer declares stays open indefinitely"
    );
}

/// The backfill is RESUMABLE and IDEMPOTENT: a batch size of one still finishes, and running
/// it twice changes nothing.
///
/// A sweep that double-inserted would make every user ambiguous with themselves and refuse
/// them all, which is a worse outcome than not running it.
#[tokio::test]
async fn the_backfill_resumes_across_batches_and_re_running_it_changes_nothing() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x9b);
    let scope = db.seed_scope(&env).await;
    activate(&db, &env, scope, &schema_with_annotated_handle()).await;

    let mut users = Vec::new();
    for n in 0..5 {
        let user = create_user(&db, &env, scope, &format!("u{n}@x.test"), None).await;
        set_traits(
            &db,
            &env,
            scope,
            &user,
            &json!({ "handle": format!("h{n}") }).to_string(),
        )
        .await;
        users.push(user);
    }
    let v2 = activate(&db, &env, scope, &schema_with_annotated_nickname()).await;
    let v3 = activate(&db, &env, scope, &schema_with_annotated_handle()).await;
    let _ = v2;

    // ONE record per batch, so the run must resume from its cursor four times.
    let job = backfill(&db, &env, scope, v3, 1).await;
    assert_eq!(
        job.processed_count, 5,
        "every identity was swept across batches"
    );

    for (n, user) in users.iter().enumerate() {
        assert_eq!(
            resolve(&db, scope, "handle", &format!("h{n}")).await,
            Some(*user),
            "u{n} must resolve after a resumed backfill"
        );
    }

    // A SECOND sweep must leave every one of them resolving, not make them ambiguous with
    // themselves.
    backfill(&db, &env, scope, v3, 100).await;
    for (n, user) in users.iter().enumerate() {
        assert_eq!(
            resolve(&db, scope, "handle", &format!("h{n}")).await,
            Some(*user),
            "u{n} stopped resolving after a SECOND backfill, so the sweep is not idempotent \
             and every user it touched twice is now ambiguous with themselves"
        );
    }
}

/// The backfill indexes an identity whose traits FAIL the active schema.
///
/// A `Migrate` would refuse that record and a `DryRun` would report it. The backfill does
/// neither: it reindexes what is stored. Those identities are the ones an operator most
/// needs to keep reachable while they fix the data.
///
/// # Why the fixture empties the index by hand
///
/// The obvious fixture (create the identity, then annotate the field) is UNREACHABLE. The
/// activation cutover gate revalidates every stored identity against the candidate schema
/// and refuses with `CutoverBlocked`, so a scope holding an invalid document cannot activate
/// anything at all until it is fixed. Measured, not assumed: that fixture failed here.
///
/// So the state under test is the OTHER one the backfill exists for, and it is the real
/// initial condition rather than a synthetic one. Migration 0131 adds an EMPTY table to a
/// live deployment: on the morning it ships, every existing identity has traits and no index
/// rows, whatever their documents say. Deleting the rows reproduces exactly that, and the
/// question is whether the sweep reaches an identity whose document does not validate.
#[tokio::test]
async fn the_backfill_indexes_an_identity_whose_traits_fail_the_active_schema() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x9c);
    let scope = db.seed_scope(&env).await;

    let strict = json!({
        "type": "object",
        "properties": {
            "handle": {"type": "string", "x-ironauth": {"identifier": true}},
            "mandatory": {"type": "string"}
        },
        "required": ["mandatory"]
    })
    .to_string();
    let version = activate(&db, &env, scope, &strict).await;

    // `admin_create` applies the visibility class but does not VALIDATE, so this writes a
    // document the active schema refuses.
    let user = create_user(
        &db,
        &env,
        scope,
        "stranded@x.test",
        Some(&json!({"handle": "stranded"}).to_string()),
    )
    .await;
    let compiled = ironauth_store::TraitSchema::compile(&strict).expect("the schema compiles");
    assert!(
        !compiled.validate(&json!({"handle": "stranded"})).is_empty(),
        "the fixture document must FAIL the active schema, or this test is the ordinary \
         case wearing a different name"
    );

    // The pre-migration state: traits present, index empty.
    sqlx::query("DELETE FROM user_trait_login_index WHERE tenant_id = $1 AND environment_id = $2")
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .execute(db.owner_pool())
        .await
        .expect("empty the index");
    assert_eq!(
        resolve(&db, scope, "handle", "stranded").await,
        None,
        "the fixture must start un-indexed, or the backfill's contribution is invisible"
    );

    let job = backfill(&db, &env, scope, version, 100).await;
    assert_eq!(
        job.status,
        ironauth_store::TraitJobStatus::Completed,
        "the backfill validates nothing, so an invalid document is not a failure for it"
    );
    assert_eq!(job.failure_count, 0);
    assert_eq!(
        resolve(&db, scope, "handle", "stranded").await,
        Some(user),
        "an identity whose document fails the active schema was SKIPPED by the sweep, so \
         the account that most needs to stay reachable while an operator fixes the data is \
         the one the backfill leaves unable to log in"
    );
}
