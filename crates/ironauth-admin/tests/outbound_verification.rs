// SPDX-License-Identifier: MIT OR Apache-2.0

//! The PER-ENVIRONMENT outbound migration verification credential (issue #250).
//!
//! Issue #58 shipped the outbound credential-verification endpoint with its
//! enablement and its shared token on the deployment-global `[admin]` config, bound
//! to ONE configured `(tenant, environment)`. Issue #250 moved both into the
//! addressed environment's own sealed `environment_secrets` row, so a multi-tenant
//! deployment can run several concurrent outbound migrations, each with an
//! independent token it can rotate on its own schedule.
//!
//! # What this file measures, and why the negative cases are the important half
//!
//! Per-environment enablement INVERTS a dependency the old shape relied on. The old
//! handler could answer "disabled" from process state before it knew anything about
//! the request; the new one cannot know whether the endpoint is enabled until it has
//! resolved the scope and read that environment's secret. A naive port would
//! therefore turn "this tenant does not exist", "this environment does not exist",
//! "this environment has the feature off", and "this environment has it on but you
//! sent no token" into four DISTINGUISHABLE answers, and the third and fourth of
//! those would be a per-environment enumeration oracle for anyone who can reach the
//! management port.
//!
//! [`every_refusal_is_one_byte_identical_not_found`] is the assertion that they are
//! not: it drives SIX states through the endpoint and requires the status, the
//! headers a client sees, and the body BYTES to be identical across all of them.
//! Every other test in this file is about the positive path or the write surface.

mod common;

use axum::http::StatusCode;
use common::{Harness, OPERATOR_TOKEN, bearer};
use ironauth_env::Env;
use ironauth_store::{ActorRef, CorrelationId, HumanId, NewAdminUser, Scope, Store, UserState};

/// A token long enough to clear the 32-byte floor the write surface enforces.
const TOKEN_A: &str = "outbound-token-alpha-of-at-least-32-bytes";
/// A DIFFERENT token, for the second environment and for the rotation.
const TOKEN_B: &str = "outbound-token-bravo-of-at-least-32-bytes";

/// The verify path for a scope.
fn verify_path(scope: Scope) -> String {
    format!(
        "/v1/tenants/{}/environments/{}/migration/verify-credential",
        scope.tenant(),
        scope.environment()
    )
}

/// The management path for a scope.
fn manage_path(scope: Scope) -> String {
    format!(
        "/v1/tenants/{}/environments/{}/migration/outbound-verification",
        scope.tenant(),
        scope.environment()
    )
}

/// A native Argon2id PHC verifier for `password`, exactly what the login path stores.
fn argon2_hash(password: &str) -> String {
    use argon2::password_hash::{PasswordHasher, SaltString};
    let salt = SaltString::encode_b64(b"outbound-per-env-salt").expect("salt");
    argon2::Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("argon2 hash")
        .to_string()
}

/// Seed one authenticatable user with a native Argon2id credential into `scope`.
async fn seed_user(store: &Store, scope: Scope, identifier: &str, password: &str) {
    let env = Env::system();
    let hash = argon2_hash(password);
    let actor = ActorRef::human(HumanId::generate(&env));
    store
        .scoped(scope)
        .acting(actor, CorrelationId::generate(&env))
        .users()
        .admin_create(
            &env,
            NewAdminUser {
                id: None,
                identifier,
                password_hash: Some(&hash),
                claims_json: None,
                external_id: None,
                state: UserState::Active,
                foreign_password_hash: None,
                foreign_password_algo: None,
                traits: None,
            },
            1_000_000,
            None,
        )
        .await
        .expect("seed user");
}

/// The request body a successor system sends.
fn verify_body(identifier: &str, password: &str) -> String {
    serde_json::json!({ "identifier": identifier, "password": password }).to_string()
}

/// (a) An environment with the feature ON verifies with ITS OWN token and refuses a
/// wrong one, and the refusal of a wrong token is the uniform not-found rather than a
/// 401 (issue #250: a 401 here would be the enablement oracle).
#[tokio::test]
async fn an_armed_environment_verifies_with_its_own_token_and_refuses_a_wrong_one() {
    let harness = Harness::start_with_outbound_verification(TOKEN_A).await;
    let scope = harness.outbound_scope();
    seed_user(
        harness.control_store(),
        scope,
        "ada@exit.test",
        "correct horse battery",
    )
    .await;
    let path = verify_path(scope);

    let (status, _headers, body) = harness
        .post_as(
            &path,
            TOKEN_A,
            "k1",
            &verify_body("ada@exit.test", "correct horse battery"),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let verdict: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        verdict["verified"], true,
        "the environment's own token verifies its own user: {body}"
    );

    // A wrong token is the uniform not-found. This is the assertion that would go RED
    // if the handler ever answered 401 again.
    let (status, _headers, body) = harness
        .post_as(
            &path,
            TOKEN_B,
            "k2",
            &verify_body("ada@exit.test", "correct horse battery"),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a wrong token is the uniform not-found, never a 401: {body}"
    );
}

/// (b) A DIFFERENT environment's token cannot verify in this one, and this one's
/// cannot verify over there: two concurrent outbound migrations are independent,
/// which is the whole point of issue #250.
#[tokio::test]
async fn one_environments_token_cannot_verify_in_another() {
    let harness = Harness::start_with_outbound_verification(TOKEN_A).await;
    let first = harness.outbound_scope();
    // A SECOND environment, armed with a DIFFERENT token. Under the pre-#250 shape
    // this state was unreachable: there was one global token and one authorized scope.
    let second = harness.seed_scope().await;
    harness.arm_outbound_verification(second, TOKEN_B).await;

    seed_user(
        harness.control_store(),
        first,
        "ada@exit.test",
        "pw-first-1",
    )
    .await;
    seed_user(
        harness.control_store(),
        second,
        "bob@exit.test",
        "pw-second-1",
    )
    .await;

    // Each environment verifies its OWN user with its OWN token.
    for (scope, token, identifier, password) in [
        (first, TOKEN_A, "ada@exit.test", "pw-first-1"),
        (second, TOKEN_B, "bob@exit.test", "pw-second-1"),
    ] {
        let (status, _h, body) = harness
            .post_as(
                &verify_path(scope),
                token,
                "k1",
                &verify_body(identifier, password),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let verdict: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(verdict["verified"], true, "own token, own user: {body}");
    }

    // And NEITHER token works in the other environment, in both directions, even
    // against a user that really exists there.
    for (scope, foreign_token, identifier, password) in [
        (first, TOKEN_B, "ada@exit.test", "pw-first-1"),
        (second, TOKEN_A, "bob@exit.test", "pw-second-1"),
    ] {
        let (status, _h, body) = harness
            .post_as(
                &verify_path(scope),
                foreign_token,
                "k2",
                &verify_body(identifier, password),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "another environment's token verifies nothing here: {body}"
        );
    }
}

/// One refusal state to drive: its label, the path, and the bearer to present (a
/// `None` bearer sends no `Authorization` header at all).
type Probe = (&'static str, String, Option<&'static str>);

/// What one probe produced: the label it was driven under, the status, the response
/// headers sorted for comparison, and the body bytes.
type Answer = (&'static str, StatusCode, Vec<(String, String)>, String);

/// (c) The INDISTINGUISHABILITY property, asserted byte for byte.
///
/// Six states, one answer. The first four are the pairs the issue brief names; the
/// last two are the states the pre-#250 shape already had and that must not regress.
/// The comparison is over the status, the response headers, and the body BYTES,
/// because two responses that agree on a status can still differ in what a client
/// receives.
#[tokio::test]
async fn every_refusal_is_one_byte_identical_not_found() {
    let harness = Harness::start_with_outbound_verification(TOKEN_A).await;
    let armed = harness.outbound_scope();
    // A live environment that has NEVER been armed.
    let disabled = harness.seed_scope().await;
    // A well-formed but never-created (tenant, environment): the ids parse in shape
    // but name no rows.
    let absent_tenant = format!(
        "/v1/tenants/{}/environments/{}/migration/verify-credential",
        ironauth_store::TenantId::generate(&Env::system()),
        disabled.environment()
    );
    let absent_environment_scope = Scope::new(
        disabled.tenant(),
        ironauth_store::EnvironmentId::generate(&Env::system()),
    );

    let body = verify_body("ada@exit.test", "correct horse battery");

    let probes: Vec<Probe> = vec![
        (
            "an absent TENANT, with a token that is valid elsewhere",
            absent_tenant,
            Some(TOKEN_A),
        ),
        (
            "an absent ENVIRONMENT under a real tenant",
            verify_path(absent_environment_scope),
            Some(TOKEN_A),
        ),
        (
            "a live environment with the feature OFF",
            verify_path(disabled),
            Some(TOKEN_A),
        ),
        (
            "an ARMED environment with NO bearer at all",
            verify_path(armed),
            None,
        ),
        (
            "an ARMED environment with a WRONG bearer",
            verify_path(armed),
            Some(TOKEN_B),
        ),
        (
            "a MALFORMED environment segment",
            format!(
                "/v1/tenants/{}/environments/env_not-a-real-id/migration/verify-credential",
                armed.tenant()
            ),
            Some(TOKEN_A),
        ),
    ];

    let mut observed: Vec<Answer> = Vec::new();
    for (label, path, token) in probes {
        let mut builder = axum::http::Request::builder()
            .method("POST")
            .uri(&path)
            .header(axum::http::header::CONTENT_TYPE, "application/json");
        if let Some(token) = token {
            builder = builder.header(axum::http::header::AUTHORIZATION, bearer(token));
        }
        let request = builder
            .body(axum::body::Body::from(body.clone()))
            .expect("request builds");
        let (status, sent_headers, response_body) = harness.send(request).await;
        let mut header_pairs: Vec<(String, String)> = sent_headers
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect();
        header_pairs.sort();
        observed.push((label, status, header_pairs, response_body));
    }

    let (reference_label, reference_status, reference_headers, reference_body) =
        observed[0].clone();
    assert_eq!(
        reference_status,
        StatusCode::NOT_FOUND,
        "the reference state must itself be the uniform not-found"
    );
    for (label, status, headers, response_body) in &observed[1..] {
        assert_eq!(
            *status, reference_status,
            "`{label}` must answer exactly what `{reference_label}` answers"
        );
        assert_eq!(
            *headers, reference_headers,
            "`{label}` must send exactly the headers `{reference_label}` sends"
        );
        assert_eq!(
            *response_body, reference_body,
            "`{label}` must send exactly the body bytes `{reference_label}` sends"
        );
    }
}

/// (d) Rotation takes effect and the old token stops working, on the very next
/// request, with no restart and no cache to invalidate.
#[tokio::test]
async fn rotation_takes_effect_and_the_old_token_stops_working() {
    let harness = Harness::start_with_outbound_verification(TOKEN_A).await;
    let scope = harness.outbound_scope();
    seed_user(
        harness.control_store(),
        scope,
        "ada@exit.test",
        "pw-rotate-1",
    )
    .await;
    let path = verify_path(scope);

    // Before: the original token verifies.
    let (status, _h, body) = harness
        .post_as(
            &path,
            TOKEN_A,
            "k1",
            &verify_body("ada@exit.test", "pw-rotate-1"),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Rotate through the management endpoint. The version must ADVANCE, which is how
    // an operator confirms the write landed without ever reading the value back.
    let (status, _h, before) = harness.get(&manage_path(scope)).await;
    assert_eq!(status, StatusCode::OK, "{before}");
    let before: serde_json::Value = serde_json::from_str(&before).expect("json");
    let (status, _h, after) = harness
        .put(
            &manage_path(scope),
            &serde_json::json!({ "token": TOKEN_B }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{after}");
    let after: serde_json::Value = serde_json::from_str(&after).expect("json");
    assert_eq!(after["enabled"], true, "still enabled after a rotation");
    assert!(
        after["version"].as_i64().expect("version") > before["version"].as_i64().expect("version"),
        "a rotation advances the stored version: {before} then {after}"
    );

    // After: the NEW token verifies and the OLD one is the uniform not-found.
    let (status, _h, body) = harness
        .post_as(
            &path,
            TOKEN_B,
            "k2",
            &verify_body("ada@exit.test", "pw-rotate-1"),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let verdict: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(verdict["verified"], true, "the rotated token works: {body}");

    let (status, _h, body) = harness
        .post_as(
            &path,
            TOKEN_A,
            "k3",
            &verify_body("ada@exit.test", "pw-rotate-1"),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the pre-rotation token stops working immediately: {body}"
    );
}

/// Disabling an environment destroys its token and returns the endpoint to the
/// uniform not-found, and disabling twice is the same success (idempotent, and not an
/// enablement oracle for a management credential either).
#[tokio::test]
async fn disabling_destroys_the_token_and_is_idempotent() {
    let harness = Harness::start_with_outbound_verification(TOKEN_A).await;
    let scope = harness.outbound_scope();
    seed_user(
        harness.control_store(),
        scope,
        "ada@exit.test",
        "pw-disable1",
    )
    .await;

    let (status, _h, body) = harness.delete(&manage_path(scope)).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let (status, _h, body) = harness
        .post_as(
            &verify_path(scope),
            TOKEN_A,
            "k1",
            &verify_body("ada@exit.test", "pw-disable1"),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a disabled environment verifies nothing, with the token that used to work: {body}"
    );

    // The metadata read agrees, and carries no version or timestamps to read.
    let (status, _h, body) = harness.get(&manage_path(scope)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let view: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(view["enabled"], false, "{body}");
    assert!(view.get("version").is_none(), "no version when off: {body}");

    // A second disable is the same 204, never a 404.
    let (status, _h, body) = harness.delete(&manage_path(scope)).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "disabling twice is the same success: {body}"
    );
}

/// The token is SEALED AT REST and is never readable back through any endpoint.
///
/// This reads the WHOLE stored row as the database OWNER (bypassing the application
/// entirely) and requires the token to appear NOWHERE in it, then requires the
/// management read to carry metadata only. Together those two are the #48 property this
/// feature inherits, MEASURED rather than assumed.
///
/// # Two scans, and why neither one alone is the test
///
/// The first version grepped the `ciphertext` column's BYTES and then separately
/// asserted that no column literally NAMED `value` exists. The second half is a guard
/// against one spelling of the hole it was aimed at: a plaintext copy landing in a column
/// called anything else satisfies it.
///
/// The obvious replacement, one `row_to_json` scan over the whole row, closes that and
/// opens a worse one, MEASURED rather than reasoned: with `put` mutated to store
/// `decoy_prefix || plaintext` in `ciphertext`, the token sat in the database in the
/// clear and the `row_to_json` assertion stayed GREEN, because `row_to_json` renders a
/// `bytea` as a HEX STRING, so a substring search over it cannot see bytes. Eight other
/// tests in the crate went red and this one, the one whose whole subject is the seal, did
/// not.
///
/// So both scans are here, because they cover different holes. The byte scan sees
/// plaintext inside the sealed column, which the JSON scan is blind to. The JSON scan
/// sees plaintext in ANY OTHER column, with no hand-written column list to keep in step
/// with the schema, which the byte scan is blind to.
#[tokio::test]
async fn the_token_is_sealed_at_rest_and_never_read_back() {
    let harness = Harness::start_with_outbound_verification(TOKEN_A).await;
    let scope = harness.outbound_scope();

    let row: (Vec<u8>, String) = sqlx::query_as(
        "SELECT ciphertext, row_to_json(t)::text FROM environment_secrets t \
         WHERE tenant_id = $1 AND environment_id = $2 AND name = $3",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind("ironauth.outbound_verification_token")
    .fetch_one(harness.db().owner_pool())
    .await
    .expect("the sealed row exists");
    let (ciphertext, stored) = row;

    // 1. The sealed column carries no plaintext, scanned as BYTES.
    assert!(
        !ciphertext.is_empty(),
        "the row carries a sealed payload rather than nothing"
    );
    assert!(
        !ciphertext
            .windows(TOKEN_A.len())
            .any(|window| window == TOKEN_A.as_bytes()),
        "the token must not appear in the sealed bytes: it is sealed under the scope's \
         envelope DEK, so a database dump yields ciphertext"
    );

    // 2. And no OTHER column carries it either, swept over the whole row rather than over
    //    a list of column names this test would have to maintain.
    assert!(
        !stored.contains(TOKEN_A),
        "the token must appear in NO column of the stored row. The row as the owner sees \
         it: {stored}"
    );

    // And the management read returns metadata only.
    let (status, _h, body) = harness.get(&manage_path(scope)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let view: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(view["enabled"], true, "{body}");
    assert!(view["version"].is_i64(), "metadata is present: {body}");
    // Deliberately NOT asserted here: that this response body does not contain the
    // token. There is no code path from `OutboundVerificationView` to a secret value
    // (it is built from `EnvironmentSecretMetadata`, whose `SELECT` does not name the
    // ciphertext column), so grepping this buffer greps a buffer the token cannot reach
    // and would stay green under any mutation of the sealing. The claim that the value
    // is unreachable is carried by the whole-row assertion above and by the store's own
    // metadata projection, not by a substring search over a response the value never
    // enters.
}

/// A SOFT-DELETED environment can still be DISARMED, and that is the whole point of the
/// asymmetry between the PUT's fence and the DELETE's (issue #250).
///
/// # The state this exists to make unreachable
///
/// Soft-deleting an environment cascades to almost nothing, so the sealed credential
/// survives it and the verify endpoint keeps answering `200` with a verified credential
/// and the user's profile. That is deliberate: a successor draining an environment is
/// exactly who is still reading it. What is NOT acceptable is that being irreversible,
/// and it was: with a liveness fence on the disable, MEASURED end to end,
///
/// ```text
/// environment DELETE            -> 204
/// POST verify-credential        -> 200 {"verified":true,"subject":"usr_...","profile":{...}}
/// DELETE outbound-verification  -> 404   (cannot disarm)
/// PUT    outbound-verification  -> 404   (cannot even rotate)
/// GET    outbound-verification  -> 200 {"enabled":true,...}
/// ```
///
/// There is no environment-restore route and no generic environment-secrets route, so a
/// decommissioned environment kept serving a live password oracle plus PII to whoever
/// held the token, remediable only by a direct database write or a full tenant crypto
/// shred.
///
/// # Why the ENVIRONMENT case and not the tenant case
///
/// Deleting the TENANT behaves differently and always did: it does not cascade
/// `deleted_at` onto its environments, so the environment stays live and the disable
/// answers `204` with no fix at all. The ENVIRONMENT delete is the broken one, so it is
/// the one driven here.
#[tokio::test]
async fn a_soft_deleted_environments_credential_can_still_be_destroyed() {
    let harness = Harness::start_with_outbound_verification(TOKEN_A).await;
    let scope = harness.outbound_scope();
    seed_user(
        harness.control_store(),
        scope,
        "ada@exit.test",
        "pw-decommission",
    )
    .await;
    let verify = verify_path(scope);
    let manage = manage_path(scope);
    let body = verify_body("ada@exit.test", "pw-decommission");

    // Armed and answering, before anything is deleted: the anti-vacuity control.
    let (status, _h, answer) = harness.post_as(&verify, TOKEN_A, "k0", &body).await;
    assert_eq!(status, StatusCode::OK, "{answer}");

    // Decommission the environment through the management API, exactly as an operator
    // would.
    let (status, _h, answer) = harness
        .delete(&format!(
            "/v1/tenants/{}/environments/{}",
            scope.tenant(),
            scope.environment()
        ))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{answer}");

    // The credential oracle SURVIVES the decommission. This is the deliberate,
    // pre-existing behaviour, asserted rather than glossed, because it is the reason
    // the disable must keep working.
    let (status, _h, answer) = harness.post_as(&verify, TOKEN_A, "k1", &body).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a soft-deleted environment still verifies, which is why the OFF SWITCH matters: {answer}"
    );
    let verdict: serde_json::Value = serde_json::from_str(&answer).expect("json");
    assert_eq!(verdict["verified"], true, "{answer}");
    assert!(
        verdict["subject"].is_string(),
        "and it hands back the subject and profile: {answer}"
    );

    // ARMING stays refused. A decommissioned environment must not acquire a NEW
    // credential oracle, and a rotation is an arming.
    let (status, _h, answer) = harness
        .put(
            &manage,
            &serde_json::json!({ "token": TOKEN_B }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "arming a decommissioned environment stays refused: {answer}"
    );

    // DISARMING works. This is the assertion that was RED before the fix.
    let (status, _h, answer) = harness.delete(&manage).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "a decommissioned environment's credential must always be destroyable: {answer}"
    );

    // And the oracle is gone, with the token that used to work.
    let (status, _h, answer) = harness.post_as(&verify, TOKEN_A, "k2", &body).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the disarm really disarmed it: {answer}"
    );

    // Still idempotent after the decommission, so a retrying operator script is not
    // told the state it asked for does not hold.
    let (status, _h, answer) = harness.delete(&manage).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{answer}");

    // And the read AGREES with the disable rather than contradicting it.
    let (status, _h, answer) = harness.get(&manage).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let view: serde_json::Value = serde_json::from_str(&answer).expect("json");
    assert_eq!(view["enabled"], false, "{answer}");
}

/// The READ and the DISABLE agree about which environments they will talk about at all
/// (issue #250).
///
/// They did not. The GET carried no environment precondition of any kind, so it answered
/// `200 {"enabled":false}` for a `(tenant, environment)` that was never created, which
/// is a confident claim about a thing that does not exist, while the DELETE next to it on
/// the same path answered the uniform not-found. Two endpoints on one path disagreeing
/// about whether their subject exists is how an operator ends up believing they have
/// disabled something they never addressed.
#[tokio::test]
async fn the_read_and_the_disable_agree_about_which_environments_exist() {
    let harness = Harness::start_with_outbound_verification(TOKEN_A).await;
    let live = harness.outbound_scope();

    // A well-formed but NEVER-CREATED environment under a real tenant.
    let absent = Scope::new(
        live.tenant(),
        ironauth_store::EnvironmentId::generate(&Env::system()),
    );
    for (label, expected_get, expected_delete) in [
        ("absent", StatusCode::NOT_FOUND, StatusCode::NOT_FOUND),
        ("live", StatusCode::OK, StatusCode::NO_CONTENT),
    ] {
        let scope = if label == "absent" { absent } else { live };
        let (status, _h, body) = harness.get(&manage_path(scope)).await;
        assert_eq!(
            status, expected_get,
            "GET at the {label} environment: {body}"
        );
        let (status, _h, body) = harness.delete(&manage_path(scope)).await;
        assert_eq!(
            status, expected_delete,
            "DELETE at the {label} environment: {body}"
        );
    }

    // And they still agree once the environment is SOFT-DELETED, in the other
    // direction: both keep answering, because the row is still addressable.
    let doomed = harness.seed_scope().await;
    harness.arm_outbound_verification(doomed, TOKEN_B).await;
    let (status, _h, body) = harness
        .delete(&format!(
            "/v1/tenants/{}/environments/{}",
            doomed.tenant(),
            doomed.environment()
        ))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, _h, body) = harness.get(&manage_path(doomed)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the read still answers for a decommissioned environment: {body}"
    );
    let (status, _h, body) = harness.delete(&manage_path(doomed)).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "and so does the disable: {body}"
    );
}

/// The `Bearer` SCHEME is matched case insensitively, per RFC 7235 section 2.1.
///
/// A case-sensitive match fails CLOSED, so this is not a security defect. It is a
/// DEBUGGING one, and a bad one specifically here: every refusal on this endpoint is the
/// same uniform not-found, so a successor system whose HTTP client normalizes the scheme
/// to `BEARER` presents a correct token and receives an answer byte-identical to "this
/// environment is not armed", with nothing anywhere to tell the two apart.
#[tokio::test]
async fn the_bearer_scheme_is_matched_case_insensitively() {
    let harness = Harness::start_with_outbound_verification(TOKEN_A).await;
    let scope = harness.outbound_scope();
    seed_user(harness.control_store(), scope, "ada@exit.test", "pw-case-1").await;
    let path = verify_path(scope);
    let body = verify_body("ada@exit.test", "pw-case-1");

    for scheme in ["Bearer", "bearer", "BEARER", "BeArEr"] {
        let request = axum::http::Request::builder()
            .method("POST")
            .uri(&path)
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .header(
                axum::http::header::AUTHORIZATION,
                format!("{scheme} {TOKEN_A}"),
            )
            .body(axum::body::Body::from(body.clone()))
            .expect("request builds");
        let (status, _h, answer) = harness.send(request).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "`{scheme}` is the same scheme as `Bearer` on the wire: {answer}"
        );
        let verdict: serde_json::Value = serde_json::from_str(&answer).expect("json");
        assert_eq!(verdict["verified"], true, "{answer}");
    }

    // A different scheme is NOT accepted, so the loop above measures case folding rather
    // than a helper that stopped looking at the scheme at all.
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(&path)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .header(
            axum::http::header::AUTHORIZATION,
            format!("Basic {TOKEN_A}"),
        )
        .body(axum::body::Body::from(body))
        .expect("request builds");
    let (status, _h, answer) = harness.send(request).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "another scheme carrying the same value authorizes nothing: {answer}"
    );
}

/// An EMPTY stored token matches nothing, driven through the store because the shipped
/// write path cannot produce one (issue #250).
///
/// This pins the BEHAVIOUR, and it deliberately does not claim to pin the line of code
/// that most obviously implements it. `stored_outbound_token`'s empty-trim guard cannot
/// be killed by any test, because two other guards already make an empty stored token
/// match nothing: `bearer_token` refuses an empty or whitespace-only PRESENTED bearer,
/// and `constant_time_eq` SHA-256s both sides, so a non-empty presented token can never
/// equal an empty stored one. Deleting the guard leaves behaviour identical in every
/// reachable state, and saying so is more useful than a row in a mutation table that
/// would be a false kill.
///
/// What IS worth pinning, and is not implied by any of that, is the whole-request
/// answer: an environment whose reserved secret holds only whitespace reports itself
/// ARMED through the management read and authorizes nobody at the verify endpoint. The
/// row is written through the store because that is how the paths that could produce it
/// would write it (the config-promotion apply, a future surface, an operator holding the
/// control-plane credential); the management PUT refuses anything under 32 bytes after
/// trimming, so it cannot.
#[tokio::test]
async fn an_empty_stored_token_authorizes_nothing() {
    let harness = Harness::start(50).await;
    let scope = harness.seed_scope().await;
    let env = Env::system();
    let actor = ActorRef::human(HumanId::generate(&env));

    harness
        .control_store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(&env))
        .environment_secrets()
        .put_under_platform_key(
            &env,
            "ironauth.outbound_verification_token",
            b"   \t\n  ",
            None,
        )
        .await
        .expect("the store seals an all-whitespace secret");

    // The metadata read says the environment is armed, which is what makes the refusal
    // below attributable to the guard rather than to an absent row.
    let (status, _h, body) = harness.get(&manage_path(scope)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let view: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(view["enabled"], true, "the row really is there: {body}");

    // And nothing verifies against it: not the whitespace it holds, and not an empty
    // bearer (which never reaches the comparison at all).
    // Only bytes an `Authorization` header can legally carry: a newline is refused by
    // the header codec long before any of this, which is a different refusal.
    for candidate in ["   ", "\t", " \t "] {
        let request = axum::http::Request::builder()
            .method("POST")
            .uri(verify_path(scope))
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .header(
                axum::http::header::AUTHORIZATION,
                format!("Bearer {candidate}"),
            )
            .body(axum::body::Body::from(verify_body("ada@exit.test", "pw")))
            .expect("request builds");
        let (status, _h, answer) = harness.send(request).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "an empty stored token must match nothing, including `{candidate:?}`: {answer}"
        );
    }
}

/// The write surface refuses a token too short to be a credential for a live password
/// oracle, and refuses it BEFORE anything is stored.
#[tokio::test]
async fn a_short_token_is_refused_and_stores_nothing() {
    let harness = Harness::start(50).await;
    let scope = harness.seed_scope().await;

    let (status, _h, body) = harness
        .put(
            &manage_path(scope),
            &serde_json::json!({ "token": "too-short" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        !body.contains("too-short"),
        "the refusal names the floor, not the token: {body}"
    );

    // Nothing was stored, so the environment is still disabled.
    let (status, _h, body) = harness.get(&manage_path(scope)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let view: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        view["enabled"], false,
        "a refused write arms nothing: {body}"
    );
}

/// The management half is a MANAGEMENT surface: it takes the management credential,
/// and a caller who is not authorized for the environment cannot use it to arm, read,
/// or disarm the environment's outbound credential.
#[tokio::test]
async fn the_management_half_requires_the_management_credential() {
    let harness = Harness::start_with_outbound_verification(TOKEN_A).await;
    let scope = harness.outbound_scope();
    let path = manage_path(scope);

    for (method, status) in [
        ("GET", StatusCode::UNAUTHORIZED),
        ("PUT", StatusCode::UNAUTHORIZED),
        ("DELETE", StatusCode::UNAUTHORIZED),
    ] {
        let request = axum::http::Request::builder()
            .method(method)
            .uri(&path)
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .header(
                axum::http::header::AUTHORIZATION,
                bearer("not-a-real-operator-token"),
            )
            .body(axum::body::Body::from(
                serde_json::json!({ "token": TOKEN_B }).to_string(),
            ))
            .expect("request builds");
        let (observed, _h, body) = harness.send(request).await;
        assert_eq!(observed, status, "{method} {path}: {body}");
    }

    // The OUTBOUND token itself is NOT a management credential: presenting it at the
    // management half is unauthorized, so a successor system holding the shared token
    // can never rotate or read its own enablement, let alone anyone else's.
    let (status, _h, body) = harness.get_as(&path, TOKEN_A).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the outbound shared token authorizes ONLY the verify endpoint: {body}"
    );

    // And the operator credential still works, so the loop above measured the
    // credential rather than a broken route.
    let (status, _h, body) = harness.get_as(&path, OPERATOR_TOKEN).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// Everything queued for the webhook fan-out in this scope, claimed and completed.
async fn queued_events(harness: &Harness, scope: Scope) -> Vec<serde_json::Value> {
    let env = Env::system();
    let claimed = harness
        .db()
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
        .expect("claim webhook events");
    for message in &claimed {
        harness
            .db()
            .store()
            .scoped(scope)
            .outbox()
            .complete(&env, message)
            .await
            .expect("complete");
    }
    claimed.into_iter().map(|message| message.payload).collect()
}

/// Arming and disarming outbound verification announce themselves, over the real routes.
///
/// The token is a live credential-verification oracle for an environment's whole user base,
/// so a consumer mirroring which environments are armed has to learn both transitions. This
/// drives the HTTP routes rather than the store because the store methods were already
/// covered by the environment-secret tests; what is new here is these two handlers PASSING an
/// event to them.
///
/// The announced payload is the secret NAME and nothing else -- no digest, no length, no
/// prefix -- because an event reaches a wider audience than the management read surface,
/// which will not return the value either. The test asserts the absence, not just the
/// presence: a leak is what would make this endpoint's event worse than no event.
///
/// The last third is the guard: disabling an ALREADY-disabled environment is a success (204,
/// deliberately not a 404), and a success that changed nothing must announce nothing.
#[tokio::test]
async fn arming_and_disarming_outbound_verification_announce_themselves() {
    let harness = Harness::start_with_outbound_verification(TOKEN_A).await;
    let scope = harness.outbound_scope();

    // Everything the fixture's own provisioning enqueued, discarded, so the counts below
    // are about these two routes alone.
    let _ = queued_events(&harness, scope).await;

    let (status, _h, body) = harness
        .put(
            &manage_path(scope),
            &serde_json::json!({ "token": TOKEN_B }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let armed = queued_events(&harness, scope).await;
    assert_eq!(armed.len(), 1, "arming announced {armed:?}");
    assert_eq!(armed[0]["type"], "environment_secret.set");
    assert_eq!(
        armed[0]["payload"]["name"], "ironauth.outbound_verification_token",
        "the NAME is what tells a consumer which reference to re-resolve: {armed:?}"
    );
    let rendered = serde_json::to_string(&armed[0]).expect("json");
    assert!(
        !rendered.contains(TOKEN_B) && !rendered.contains(TOKEN_A),
        "the token itself reached the wire: {rendered}"
    );
    assert!(
        armed[0]["payload"].get("value").is_none()
            && armed[0]["payload"].get("digest").is_none()
            && armed[0]["payload"].get("length").is_none(),
        "nothing DERIVED from the value may travel either: a digest of a low-entropy secret \
         is guessable and a length narrows a search: {armed:?}"
    );

    let (status, _h, body) = harness.delete(&manage_path(scope)).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let disarmed = queued_events(&harness, scope).await;
    assert_eq!(disarmed.len(), 1, "disarming announced {disarmed:?}");
    assert_eq!(
        disarmed[0]["type"], "environment_secret.deleted",
        "a disarm announced as a set would leave a consumer believing the oracle is still live"
    );
    assert_eq!(
        disarmed[0]["payload"]["name"],
        "ironauth.outbound_verification_token"
    );

    // A second disable is the same 204, and changes nothing.
    let (status, _h, body) = harness.delete(&manage_path(scope)).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let again = queued_events(&harness, scope).await;
    assert!(
        again.is_empty(),
        "a success that changed no row must announce nothing: {again:?}"
    );
}
