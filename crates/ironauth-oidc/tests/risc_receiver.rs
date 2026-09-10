// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Google Cross-Account Protection receiver end to end (issue #144, criteria 4 and 5),
//! against a real Postgres and the real protocol router.
//!
//! # What this owes
//!
//! - **Criterion 4**: a simulated Google `credential-compromise` SET triggers the configured
//!   protection for the LINKED IronAuth user, with an audit trail. Both halves of the
//!   protection are asserted, and so is the link: a receiver that acted on the wrong user,
//!   or on nobody, would be worse than one that did nothing.
//! - **Criterion 5**: inbound validation rejects a wrong issuer, a wrong audience, a bad
//!   signature, and a stale issuance time.
//! - The issue's adversarial list: forged SETs, replayed SETs, wrong-audience.
//!
//! Every rejection test asserts that NOTHING happened as well as that the status was 400.
//! A receiver that refused the token after revoking the sessions would pass a status-only
//! assertion while being the exact failure worth preventing.

#![cfg(feature = "testing")]

mod common;

use std::time::SystemTime;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::Harness;
use ironauth_config::RiscReceiverConfig;
use ironauth_jose::{EmissionOptions, JwkSet, SigningKey, sign_jws};
use ironauth_store::{
    AccountLinkId, AccountLinkMethod, CorrelationId, NewAccountLink, TrustedDeviceRevokeReason,
    UserId,
};
use serde_json::json;

const GOOGLE_ISS: &str = "https://accounts.google.com";
const GOOGLE_KID: &str = "google-key-1";
const GOOGLE_SUB: &str = "1147890123456789";
const CONNECTOR: &str = "con_google";
const CREDENTIAL_COMPROMISE: &str =
    "https://schemas.openid.net/secevent/risc/event-type/credential-compromise";

fn transmitter_key(seed_byte: u8) -> SigningKey {
    SigningKey::ed25519_from_seed(Some(GOOGLE_KID.to_owned()), &[seed_byte; 32])
        .expect("ed25519 key from seed")
}

fn jwks_of(key: &SigningKey) -> String {
    JwkSet::from_signing_keys(std::iter::once(key))
        .expect("jwks from signing key")
        .to_json()
        .expect("jwks to json")
}

fn receiver_config(key: &SigningKey) -> RiscReceiverConfig {
    RiscReceiverConfig {
        enabled: true,
        issuer: GOOGLE_ISS.to_owned(),
        jwks: jwks_of(key),
        algorithms: vec!["EdDSA".to_owned()],
        connector_id: CONNECTOR.to_owned(),
        ..RiscReceiverConfig::default()
    }
}

fn epoch_secs(at: SystemTime) -> i64 {
    i64::try_from(
        at.duration_since(SystemTime::UNIX_EPOCH)
            .expect("after epoch")
            .as_secs(),
    )
    .expect("fits i64")
}

/// A signed RISC SET in the shape Google Cross-Account Protection sends.
#[expect(
    clippy::too_many_arguments,
    reason = "each claim is overridable per test"
)]
fn signed_set(
    key: &SigningKey,
    iss: &str,
    aud: &str,
    iat: i64,
    jti: &str,
    event_type: &str,
    subject_iss: &str,
    subject_sub: &str,
) -> String {
    // NO `exp`: SSF 1.0 section 4.1.7 makes its absence a MUST, and this is the shape a
    // conforming transmitter actually sends.
    let claims = json!({
        "iss": iss,
        "aud": aud,
        "iat": iat,
        "jti": jti,
        "sub_id": { "format": "iss_sub", "iss": subject_iss, "sub": subject_sub },
        "events": { event_type: {} }
    });
    let payload = serde_json::to_vec(&claims).expect("claims serialize");
    sign_jws(key, &payload, &EmissionOptions::new()).expect("sign the SET")
}

fn push(path_scope: &str, set: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/t/{path_scope}/risc/events"))
        .header(header::CONTENT_TYPE, "application/secevent+jwt")
        .body(Body::from(set))
        .expect("request")
}

fn scope_path_and_audience(harness: &Harness) -> (String, String) {
    let scope = harness.scope();
    (
        format!("{}/e/{}", scope.tenant(), scope.environment()),
        harness.state().issuer_for(&scope),
    )
}

/// Seed a user and link it to the Google subject, as a social sign-in would.
async fn seed_linked_user(harness: &Harness, identifier: &str) -> UserId {
    let env = harness.state().env().clone();
    let scope = harness.scope();
    let subject = harness.seed_user(identifier, "correct horse battery").await;
    let user = harness
        .state()
        .store()
        .scoped(scope)
        .users()
        .parse_id(&subject)
        .expect("parse the seeded user");
    let external_id = ironauth_oidc::federated_external_id(GOOGLE_ISS, GOOGLE_SUB);
    harness
        .state()
        .store()
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .account_links()
        .create(
            &env,
            &AccountLinkId::generate(&env, &scope),
            NewAccountLink {
                user_id: &user,
                connector_id: CONNECTOR,
                external_id: &external_id,
                email_verified: true,
                link_method: AccountLinkMethod::AutoVerified,
            },
        )
        .await
        .expect("link the google account");
    user
}

/// How many of this user's sessions are still live.
async fn live_sessions(harness: &Harness, user: &UserId) -> i64 {
    let scope = harness.scope();
    sqlx::query_scalar(
        "SELECT count(*) FROM sessions \
         WHERE tenant_id = $1 AND environment_id = $2 AND subject = $3 AND ended_at IS NULL",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(user.to_string())
    .fetch_one(harness.db().owner_pool())
    .await
    .expect("count live sessions")
}

/// How many of this user's remembered devices are still trusted.
async fn live_devices(harness: &Harness, user: &UserId) -> i64 {
    let scope = harness.scope();
    sqlx::query_scalar(
        "SELECT count(*) FROM trusted_devices \
         WHERE tenant_id = $1 AND environment_id = $2 AND subject = $3 AND revoked_at IS NULL",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(user.to_string())
    .fetch_one(harness.db().owner_pool())
    .await
    .expect("count live devices")
}

/// The audit actions recorded for this scope, newest last.
async fn audit_actions(harness: &Harness) -> Vec<String> {
    let scope = harness.scope();
    sqlx::query_scalar(
        "SELECT action FROM audit_log \
         WHERE tenant_id = $1 AND environment_id = $2 ORDER BY recorded_at, id",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_all(harness.db().owner_pool())
    .await
    .expect("read the audit log")
}

/// Seed one live session and one remembered device for `user`, so a protection has
/// something to take away and a test can tell "revoked" from "there was nothing there".
async fn seed_session_and_device(harness: &Harness, user: &UserId, nonce: u8) {
    let env = harness.state().env().clone();
    let scope = harness.scope();
    let store = harness.state().store().clone();
    let session = ironauth_store::SessionId::generate(&env, &scope);
    store
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .sessions()
        .rotate(
            &env,
            &session,
            None,
            ironauth_store::NewSession {
                impersonation: None,
                subject: &user.to_string(),
                auth_methods: "pwd",
                auth_time_micros: 0,
                idle_expires_micros: 4_102_444_800_000_000,
                absolute_expires_micros: 4_102_444_800_000_000,
                user_agent: None,
                peer_ip: None,
            },
        )
        .await
        .expect("seed a session");
    store
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .trusted_devices()
        .remember(
            &env,
            user,
            ironauth_store::NewTrustedDevice {
                device_secret_hash: &[nonce; 32],
                session_lineage: &session.to_string(),
                user_agent: "probe/1.0",
                coarse_location: "",
                max_age_expires_micros: 4_102_444_800_000_000,
                idle_expires_micros: 4_102_444_800_000_000,
            },
        )
        .await
        .expect("remember a device");
}

#[tokio::test]
async fn a_credential_compromise_set_revokes_the_linked_users_sessions_and_devices() {
    // CRITERION 4, end to end: a simulated Google Cross-Account Protection SET reaches the
    // real router, is verified against the configured transmitter, resolves through the
    // account link to the LOCAL user, and applies both halves of the configured protection
    // with an audit trail.
    //
    // BOTH HALVES ARE ASSERTED. Revoking sessions alone would pass a test that only counted
    // sessions, and would leave the attacker able to walk back in with one password because
    // the remembered device still lets the next sign-in skip the strong factor.
    let mut harness = Harness::start_store_backed().await;
    let key = transmitter_key(1);
    let user = seed_linked_user(&harness, "victim@example.test").await;
    seed_session_and_device(&harness, &user, 1).await;
    harness.enable_risc_receiver(&receiver_config(&key));
    let (path, audience) = scope_path_and_audience(&harness);
    let now = epoch_secs(harness.state().now());

    assert_eq!(live_sessions(&harness, &user).await, 1, "seeded session");
    assert_eq!(live_devices(&harness, &user).await, 1, "seeded device");
    let before = audit_actions(&harness).await.len();

    let set = signed_set(
        &key,
        GOOGLE_ISS,
        &audience,
        now,
        "jti-compromise-1",
        CREDENTIAL_COMPROMISE,
        GOOGLE_ISS,
        GOOGLE_SUB,
    );
    let (status, _headers, body) = harness.send(push(&path, set)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");

    assert_eq!(
        live_sessions(&harness, &user).await,
        0,
        "the compromised user's sessions were not revoked"
    );
    assert_eq!(
        live_devices(&harness, &user).await,
        0,
        "the compromised user's remembered devices survived, so the next sign-in still \
         skips the strong factor"
    );
    // THE AUDIT TRAIL. Asserted as "the protections wrote rows" rather than by naming the
    // exact actions, because the store owns those names and this test is about the
    // receiver having gone through the audited path at all rather than around it.
    let after = audit_actions(&harness).await;
    assert!(
        after.len() > before,
        "the protections left no audit trail: {after:?}"
    );
}

#[tokio::test]
async fn the_device_revocation_records_the_upstream_compromise_reason() {
    // The reason column is read by a human deciding whether a revocation was expected, and
    // #144 added a value for exactly this case. Recording it as `admin` would put an
    // operator's name on something no operator did.
    let mut harness = Harness::start_store_backed().await;
    let key = transmitter_key(1);
    let user = seed_linked_user(&harness, "reason@example.test").await;
    seed_session_and_device(&harness, &user, 2).await;
    harness.enable_risc_receiver(&receiver_config(&key));
    let (path, audience) = scope_path_and_audience(&harness);
    let now = epoch_secs(harness.state().now());

    let set = signed_set(
        &key,
        GOOGLE_ISS,
        &audience,
        now,
        "jti-reason",
        CREDENTIAL_COMPROMISE,
        GOOGLE_ISS,
        GOOGLE_SUB,
    );
    let (status, _headers, body) = harness.send(push(&path, set)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");

    let scope = harness.scope();
    let reason: String = sqlx::query_scalar(
        "SELECT revoke_reason FROM trusted_devices \
         WHERE tenant_id = $1 AND environment_id = $2 AND subject = $3",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(user.to_string())
    .fetch_one(harness.db().owner_pool())
    .await
    .expect("read the revoke reason");
    assert_eq!(
        reason,
        TrustedDeviceRevokeReason::UpstreamCompromise.as_str()
    );
}

#[tokio::test]
async fn every_invalid_set_is_refused_and_protects_nothing() {
    // CRITERION 5 and the issue's adversarial list in one sweep: a forged signature, an
    // unknown issuer, a wrong audience, and a stale issuance time.
    //
    // EACH CASE ASSERTS THAT NOTHING HAPPENED, not merely that the status was 400. A
    // receiver that revoked the sessions and THEN refused the token would pass a
    // status-only assertion while being the exact failure worth preventing.
    let mut harness = Harness::start_store_backed().await;
    let key = transmitter_key(1);
    let wrong_key = transmitter_key(2);
    let user = seed_linked_user(&harness, "untouched@example.test").await;
    seed_session_and_device(&harness, &user, 3).await;
    harness.enable_risc_receiver(&receiver_config(&key));
    let (path, audience) = scope_path_and_audience(&harness);
    let now = epoch_secs(harness.state().now());

    let mint = |k: &SigningKey, iss: &str, aud: &str, iat: i64, jti: &str| {
        signed_set(
            k,
            iss,
            aud,
            iat,
            jti,
            CREDENTIAL_COMPROMISE,
            GOOGLE_ISS,
            GOOGLE_SUB,
        )
    };

    for (label, set) in [
        // A VALID JWS signed by a key this receiver does not trust.
        (
            "forged signature",
            mint(&wrong_key, GOOGLE_ISS, &audience, now, "jti-forged"),
        ),
        // A transmitter this deployment never registered.
        (
            "unknown issuer",
            mint(&key, "https://attacker.example", &audience, now, "jti-iss"),
        ),
        // Minted for a DIFFERENT deployment: a token captured elsewhere must not act here.
        (
            "wrong audience",
            mint(
                &key,
                GOOGLE_ISS,
                "https://other.example/t/x/e/y",
                now,
                "jti-aud",
            ),
        ),
        // Impeccable in every other way, and hours older than the configured window.
        (
            "stale issuance time",
            mint(&key, GOOGLE_ISS, &audience, now - 86_400, "jti-stale"),
        ),
    ] {
        let (status, _headers, body) = harness.send(push(&path, set)).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{label} must be refused: {body}"
        );
        assert_eq!(
            live_sessions(&harness, &user).await,
            1,
            "{label} revoked a session before refusing the token"
        );
        assert_eq!(
            live_devices(&harness, &user).await,
            1,
            "{label} revoked a device before refusing the token"
        );
    }
}

#[tokio::test]
async fn a_replayed_set_acts_exactly_once() {
    // THE PROTECTIONS ARE NOT IDEMPOTENT the way a delivery is. Re-applying them would end
    // sessions the user has since legitimately started and revoke devices they have since
    // re-trusted, so an attacker holding one captured genuine SET could re-lock the account
    // at will without forging anything.
    //
    // The second delivery is accepted rather than refused: the transmitter did nothing
    // wrong and must not be told to retry. What must not happen is the ACTION running
    // twice, which is why the user re-establishes a session between the two and it survives.
    let mut harness = Harness::start_store_backed().await;
    let key = transmitter_key(1);
    let user = seed_linked_user(&harness, "replay@example.test").await;
    seed_session_and_device(&harness, &user, 4).await;
    harness.enable_risc_receiver(&receiver_config(&key));
    let (path, audience) = scope_path_and_audience(&harness);
    let now = epoch_secs(harness.state().now());

    let set = signed_set(
        &key,
        GOOGLE_ISS,
        &audience,
        now,
        "jti-replayed",
        CREDENTIAL_COMPROMISE,
        GOOGLE_ISS,
        GOOGLE_SUB,
    );
    let (status, _headers, body) = harness.send(push(&path, set.clone())).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(live_sessions(&harness, &user).await, 0);

    // The user recovers and signs in again.
    seed_session_and_device(&harness, &user, 5).await;
    assert_eq!(live_sessions(&harness, &user).await, 1);

    let (status, _headers, body) = harness.send(push(&path, set)).await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "a replay is not the transmitter's fault: {body}"
    );
    assert_eq!(
        live_sessions(&harness, &user).await,
        1,
        "a replayed SET re-revoked the session the user legitimately re-established"
    );
    assert_eq!(
        live_devices(&harness, &user).await,
        1,
        "a replayed SET re-revoked the device the user legitimately re-trusted"
    );
}

#[tokio::test]
async fn a_subject_this_deployment_does_not_know_is_accepted_and_does_nothing() {
    // The transmitter is entitled to tell us about accounts that never signed in here.
    // Answering an error would have it retry forever; acting would be impossible. The
    // linked user beside it is untouched, which is what separates "resolved to nobody"
    // from "resolved to the wrong person".
    let mut harness = Harness::start_store_backed().await;
    let key = transmitter_key(1);
    let user = seed_linked_user(&harness, "bystander@example.test").await;
    seed_session_and_device(&harness, &user, 6).await;
    harness.enable_risc_receiver(&receiver_config(&key));
    let (path, audience) = scope_path_and_audience(&harness);
    let now = epoch_secs(harness.state().now());

    let set = signed_set(
        &key,
        GOOGLE_ISS,
        &audience,
        now,
        "jti-stranger",
        CREDENTIAL_COMPROMISE,
        GOOGLE_ISS,
        "999999999999999",
    );
    let (status, _headers, body) = harness.send(push(&path, set)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(
        live_sessions(&harness, &user).await,
        1,
        "a signal about a stranger ended somebody else's session"
    );
    assert_eq!(live_devices(&harness, &user).await, 1);
}

#[tokio::test]
async fn an_event_type_outside_the_protective_set_changes_nothing() {
    // `identifier-changed` is a fact to re-read, not a reason to end sessions. A receiver
    // that acted on every RISC type would turn a Google display-name change into a forced
    // sign-out for every social-login user.
    let mut harness = Harness::start_store_backed().await;
    let key = transmitter_key(1);
    let user = seed_linked_user(&harness, "renamed@example.test").await;
    seed_session_and_device(&harness, &user, 7).await;
    harness.enable_risc_receiver(&receiver_config(&key));
    let (path, audience) = scope_path_and_audience(&harness);
    let now = epoch_secs(harness.state().now());

    let set = signed_set(
        &key,
        GOOGLE_ISS,
        &audience,
        now,
        "jti-identifier",
        "https://schemas.openid.net/secevent/risc/event-type/identifier-changed",
        GOOGLE_ISS,
        GOOGLE_SUB,
    );
    let (status, _headers, body) = harness.send(push(&path, set)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(live_sessions(&harness, &user).await, 1);
    assert_eq!(live_devices(&harness, &user).await, 1);
}

#[tokio::test]
async fn the_endpoint_404s_unless_the_receiver_is_enabled() {
    // Off is a uniform 404 rather than a 501: a transmitter probing a deployment that has
    // not enabled the receiver learns that it does not implement it, which is true.
    let harness = Harness::start_store_backed().await;
    let key = transmitter_key(1);
    let (path, audience) = scope_path_and_audience(&harness);
    let now = epoch_secs(harness.state().now());
    let set = signed_set(
        &key,
        GOOGLE_ISS,
        &audience,
        now,
        "jti-off",
        CREDENTIAL_COMPROMISE,
        GOOGLE_ISS,
        GOOGLE_SUB,
    );
    let (status, _headers, _body) = harness.send(push(&path, set)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_email_subject_is_refused_rather_than_matched_by_address() {
    // THE DECLARED FORMAT IS CHECKED, not just the members that happen to be present.
    //
    // This subject declares `email` AND carries `iss`/`sub`, which is the shape that makes
    // the format check load-bearing: without it the parser would read the two members it
    // wants, ignore the label, and resolve the link. Mutation-checking caught that an
    // earlier version of this test used an email subject with NO `iss`/`sub`, so it passed
    // because the members were missing and would have passed with the format check
    // removed. A receiver that trusts members while ignoring the label its transmitter put
    // on them is reading a different subject from the one that was sent.
    //
    // The refusal is a 400 rather than a silent no-op because the token is well-formed for
    // a shape this receiver does not implement, and a transmitter should learn that rather
    // than believe it was handled.
    let mut harness = Harness::start_store_backed().await;
    let key = transmitter_key(1);
    let user = seed_linked_user(&harness, "byaddress@example.test").await;
    seed_session_and_device(&harness, &user, 40).await;
    harness.enable_risc_receiver(&receiver_config(&key));
    let (path, audience) = scope_path_and_audience(&harness);
    let now = epoch_secs(harness.state().now());

    let claims = json!({
        "iss": GOOGLE_ISS,
        "aud": audience,
        "iat": now,
        "jti": "jti-by-email",
        "sub_id": {
            "format": "email",
            "email": "byaddress@example.test",
            // PRESENT AND CORRECT, so the only thing refusing this token is the label.
            "iss": GOOGLE_ISS,
            "sub": GOOGLE_SUB
        },
        "events": { CREDENTIAL_COMPROMISE: {} }
    });
    let payload = serde_json::to_vec(&claims).expect("claims serialize");
    let set = sign_jws(&key, &payload, &EmissionOptions::new()).expect("sign the SET");

    let (status, _headers, body) = harness.send(push(&path, set)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        live_sessions(&harness, &user).await,
        1,
        "a subject named only by address ended a linked user's session"
    );
}

#[tokio::test]
async fn a_set_carrying_several_events_is_refused_rather_than_partly_applied() {
    // RFC 8417 permits more than one event in a SET. Acting on the first and dropping the
    // rest would leave "we handled part of it" as the outcome, which the audit trail cannot
    // express and the transmitter cannot detect. Refusing is the only honest answer until
    // the multi-event shape is actually implemented.
    let mut harness = Harness::start_store_backed().await;
    let key = transmitter_key(1);
    let user = seed_linked_user(&harness, "multi@example.test").await;
    seed_session_and_device(&harness, &user, 41).await;
    harness.enable_risc_receiver(&receiver_config(&key));
    let (path, audience) = scope_path_and_audience(&harness);
    let now = epoch_secs(harness.state().now());

    let claims = json!({
        "iss": GOOGLE_ISS,
        "aud": audience,
        "iat": now,
        "jti": "jti-multi",
        "sub_id": { "format": "iss_sub", "iss": GOOGLE_ISS, "sub": GOOGLE_SUB },
        "events": {
            CREDENTIAL_COMPROMISE: {},
            "https://schemas.openid.net/secevent/risc/event-type/identifier-changed": {}
        }
    });
    let payload = serde_json::to_vec(&claims).expect("claims serialize");
    let set = sign_jws(&key, &payload, &EmissionOptions::new()).expect("sign the SET");

    let (status, _headers, body) = harness.send(push(&path, set)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(live_sessions(&harness, &user).await, 1);
}

#[tokio::test]
async fn a_subject_at_another_issuer_is_refused() {
    // `sub_id.iss` is a value INSIDE the token, so it is chosen by whoever minted it, and
    // it feeds straight into the account-link lookup that decides whose sessions end. A
    // transmitter may speak only about its OWN subjects.
    //
    // Today the deployment's connector holds only Google links, so a foreign subject would
    // also fail to resolve -- which is exactly why this test pins the CHECK rather than the
    // outcome: point `connector_id` at a connector carrying links from several issuers and
    // the resolve stops being a fence, while this stays one.
    let mut harness = Harness::start_store_backed().await;
    let key = transmitter_key(1);
    let user = seed_linked_user(&harness, "foreignsub@example.test").await;
    seed_session_and_device(&harness, &user, 42).await;
    harness.enable_risc_receiver(&receiver_config(&key));
    let (path, audience) = scope_path_and_audience(&harness);
    let now = epoch_secs(harness.state().now());

    let set = signed_set(
        &key,
        GOOGLE_ISS,
        &audience,
        now,
        "jti-foreign-subject",
        CREDENTIAL_COMPROMISE,
        // The TRANSMITTER is Google and the token is genuinely Google-signed; only the
        // subject claims to belong to somebody else.
        "https://login.microsoftonline.com/common/v2.0",
        GOOGLE_SUB,
    );
    let (status, _headers, body) = harness.send(push(&path, set)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(live_sessions(&harness, &user).await, 1);
    assert_eq!(live_devices(&harness, &user).await, 1);
}
