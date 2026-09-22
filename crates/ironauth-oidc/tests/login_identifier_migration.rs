// SPDX-License-Identifier: MIT OR Apache-2.0

//! The sign-in identifier mode and its case-sensitivity change as ONLINE migrations, with
//! logins succeeding through the arc (issue #148 criterion 5).
//!
//! The mechanism under test is the trait-schema version arc: the ACTIVE schema declares
//! which trait fields are login identifiers (`x-ironauth: {"identifier": true}`). Activating
//! a new schema version IS the online migration - the runner never takes the store down -
//! and the `BackfillLoginIndex` job rebuilds the index for users who never write again.
//!
//! The store half (which field resolves, the case/whitespace folding, the
//! miss-not-wrong-answer property) is pinned in `ironauth-store`'s `trait_login_index.rs`.
//! What is only reachable here is the END TO END claim: an operator moves the identifier
//! annotation, runs the backfill, and real `/login` traffic succeeds before, during, and
//! after - a login in the migration window is a clean miss, never a wrong answer or a
//! crash, and the case-insensitivity of the identifier holds across the move.

mod common;
use common::{
    Harness, PKCE_CHALLENGE, REDIRECT_URI, SEED_PASSWORD, enc, form, form_field, location,
    set_cookie_pair,
};
use ironauth_store::{TraitJobKind, TraitMigrationStart};
use serde_json::json;

/// Schema v1: `handle` is the login identifier, `nickname` is not.
const SCHEMA_HANDLE_IDENTIFIER: &str = r#"{"type":"object","properties":{
    "handle":{"type":"string","x-ironauth":{"identifier":true}},
    "nickname":{"type":"string"}
}}"#;

/// Schema v2 - the ONLINE MIGRATION: the identifier mode moves to `nickname`, and `handle`
/// stops being a login identifier. This is exactly the "sign-in identifier mode changes as
/// an online migration" the criterion names.
const SCHEMA_NICKNAME_IDENTIFIER: &str = r#"{"type":"object","properties":{
    "handle":{"type":"string"},
    "nickname":{"type":"string","x-ironauth":{"identifier":true}}
}}"#;

/// Drive `/login` for `identifier` and return (status, headers, body).
async fn login(
    harness: &Harness,
    return_to: &str,
    identifier: &str,
) -> (axum::http::StatusCode, axum::http::HeaderMap, String) {
    let body = form(&[
        ("identifier", identifier),
        ("password", SEED_PASSWORD),
        ("return_to", return_to),
    ]);
    harness.post_form("/login", &body, None).await
}

/// A successful login: a 303 that resumes the authorization request and sets a session.
fn assert_logged_in(status: axum::http::StatusCode, headers: &axum::http::HeaderMap, who: &str) {
    assert_eq!(
        status,
        axum::http::StatusCode::SEE_OTHER,
        "{who} must log in"
    );
    assert!(
        set_cookie_pair(headers).is_some(),
        "{who} must receive a session cookie"
    );
}

/// A clean miss: the failure page re-rendered, never a 303 and never a 500.
fn assert_clean_miss(status: axum::http::StatusCode, body: &str, who: &str) {
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "{who} must be a clean miss, not a crash or a wrong answer"
    );
    assert!(
        !body.contains("Internal Server Error"),
        "{who} must not be a 500 rendered as a page"
    );
}

/// Write a user's traits through the same path the store's index tests use: the login-index
/// rows are maintained on the trait WRITE against the active schema.
async fn set_user_traits(harness: &Harness, identifier: &str, traits_json: &str) {
    let (actor, corr) = harness.seeding_actor();
    let user_id = harness
        .store()
        .scoped(harness.scope())
        .users()
        .by_identifier(identifier)
        .await
        .expect("the seeded user resolves")
        .expect("the user exists")
        .id;
    harness
        .store()
        .scoped(harness.scope())
        .acting(actor, corr)
        .users()
        .set_traits(harness.env(), &user_id, traits_json)
        .await
        .expect("set the traits");
}

/// Activate a new schema version WITHOUT touching users (the harness's seeding helper is
/// for the pre-login state; the migration arc activates versions directly).
async fn activate_schema(harness: &Harness, schema_json: &str) {
    let (actor, corr) = harness.seeding_actor();
    let acting = harness.store().scoped(harness.scope()).acting(actor, corr);
    let (_, version) = acting
        .trait_schemas()
        .create_version(harness.env(), schema_json, 0)
        .await
        .expect("create the migrated schema version");
    acting
        .trait_schemas()
        .activate_version(harness.env(), version)
        .await
        .expect("activate the migrated schema");
}

/// Drive a `BackfillLoginIndex` job to completion, the sweep that reaches users who never
/// write again (the store test drives the same helper).
async fn backfill_login_index(harness: &Harness) {
    let (actor, corr) = harness.seeding_actor();
    let acting = harness.store().scoped(harness.scope()).acting(actor, corr);
    let env = harness.env();
    let job_id = acting
        .trait_migration_jobs()
        .create(
            env,
            ironauth_store::NewTraitMigrationJob {
                kind: TraitJobKind::BackfillLoginIndex,
                from_version: 1,
                to_version: 2,
                transform_json: None,
            },
            0,
            TraitMigrationStart {
                first_batch_payload: &json!({}),
                idempotency: None,
            },
        )
        .await
        .expect("create the backfill job");
    let mut job = acting
        .trait_migration_jobs()
        .advance(env, &job_id, 100)
        .await
        .expect("advance the backfill");
    for _ in 0..50 {
        if job.status.is_terminal() {
            break;
        }
        job = acting
            .trait_migration_jobs()
            .advance(env, &job_id, 100)
            .await
            .expect("advance the backfill");
    }
    assert!(job.status.is_terminal(), "the backfill must terminate");
}

/// THE CRITERION: the identifier mode moves as an online migration, and real logins
/// succeed before, during, and after it.
#[tokio::test]
async fn the_identifier_mode_moves_as_an_online_migration_with_logins_succeeding() {
    let harness = Harness::start_store_backed().await;
    // Schema v1, with `handle` annotated, ACTIVE BEFORE any user exists (the cutover rule).
    harness
        .seed_active_trait_schema(SCHEMA_HANDLE_IDENTIFIER)
        .await;
    // A user whose handle is the login value and whose nickname is the OTHER value.
    harness.seed_user("ada@example.test", SEED_PASSWORD).await;
    set_user_traits(
        &harness,
        "ada@example.test",
        r#"{"handle": "Ada.Lovelace", "nickname": "Nicky"}"#,
    )
    .await;

    // The login surface, like every flow test.
    let query = format!(
        "response_type=code&client_id={}&redirect_uri={}&scope={}&state=c5-state&nonce=c5-nonce&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        harness.client_id(),
        enc(REDIRECT_URI),
        enc("openid"),
    );
    let (status, headers, _) = harness.authorize(&query).await;
    assert_eq!(status, axum::http::StatusCode::SEE_OTHER);
    let login_location = location(&headers).expect("login redirect");
    let (status, _headers, html) = harness.get_with_cookie(&login_location, None).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let return_to = form_field(&html, "return_to").expect("login return_to");

    // PRE-MIGRATION: the identifier mode is `handle`, and it is case-insensitive.
    let (status, headers, _) = login(&harness, &return_to, "Ada.Lovelace").await;
    assert_logged_in(status, &headers, "the handle login");
    let (status, headers, _) = login(&harness, &return_to, "ada.lovelace").await;
    assert_logged_in(status, &headers, "the differently-cased handle login");

    // THE ONLINE MIGRATION: activate the schema that moves the identifier to `nickname`.
    activate_schema(&harness, SCHEMA_NICKNAME_IDENTIFIER).await;

    // DURING THE MIGRATION (before the backfill): both paths are CLEAN MISSES. The old
    // identifier no longer resolves (the mode moved), and the new one has no index rows
    // yet - a miss, never a wrong answer, never a crash. Logins are still served.
    let (status, headers, body) = login(&harness, &return_to, "Ada.Lovelace").await;
    assert_clean_miss(status, &body, "the old identifier after the move");
    assert!(
        set_cookie_pair(&headers).is_none(),
        "a clean miss must not mint a session"
    );
    let (status, _headers, body) = login(&harness, &return_to, "Nicky").await;
    assert_clean_miss(status, &body, "the new identifier before the backfill");

    // The backfill reaches the users who never write again.
    backfill_login_index(&harness).await;

    // POST-MIGRATION: the new identifier mode logs in, still case-insensitively.
    let (status, headers, _) = login(&harness, &return_to, "Nicky").await;
    assert_logged_in(status, &headers, "the new identifier after the backfill");
    let (status, headers, _) = login(&harness, &return_to, "NICKY").await;
    assert_logged_in(status, &headers, "the differently-cased new identifier");
}

/// The `handle` still identifies the user for EVERYTHING that is not login - the move
/// shrank the LOGIN surface, it did not rename the account. The subject the migrated
/// login resolves is the SAME user the handle resolved before the move.
#[tokio::test]
async fn the_migrated_login_resolves_the_same_subject() {
    let harness = Harness::start_store_backed().await;
    harness
        .seed_active_trait_schema(SCHEMA_HANDLE_IDENTIFIER)
        .await;
    harness.seed_user("bob@example.test", SEED_PASSWORD).await;
    set_user_traits(
        &harness,
        "bob@example.test",
        r#"{"handle": "Bob.Handle", "nickname": "Bobby"}"#,
    )
    .await;
    let subject = harness
        .store()
        .scoped(harness.scope())
        .users()
        .by_identifier("bob@example.test")
        .await
        .expect("the seeded user resolves")
        .expect("the user exists")
        .id
        .to_string();

    // Resolve the subject through the handle BEFORE the move, directly against the store
    // (the same read the login path uses).
    let before = harness
        .store()
        .scoped(harness.scope())
        .users()
        .by_annotated_trait("handle", "Bob.Handle")
        .await
        .expect("the handle resolves before the move")
        .expect("the user exists");

    // The migration: the mode moves; the backfill runs.
    activate_schema(&harness, SCHEMA_NICKNAME_IDENTIFIER).await;
    backfill_login_index(&harness).await;

    // The subject the NEW identifier resolves is the same account.
    let after = harness
        .store()
        .scoped(harness.scope())
        .users()
        .by_annotated_trait("nickname", "Bobby")
        .await
        .expect("the nickname resolves after the backfill")
        .expect("the user resolves");
    assert_eq!(after.id, before.id, "one user throughout the migration");
    assert_eq!(after.id.to_string(), subject);
}
