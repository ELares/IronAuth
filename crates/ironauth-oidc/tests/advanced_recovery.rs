// SPDX-License-Identifier: MIT OR Apache-2.0

//! Advanced recovery modes (issue #82, PR 3), against a real Postgres with an injected clock.
//!
//! These pin the acceptance-critical, CI-permanent negatives:
//!
//! - ALL three modes complete THROUGH the #81 gate: a mode never bypasses the `hold_until`
//!   delay window, and the downgrade invariant (`gate_factor_removal`) still blocks removing a
//!   stronger factor;
//! - trusted-contact: `required_confirmations` DISTINCT contacts are required, a single
//!   contact confirming twice does NOT reach a threshold of two, a confirmation token is
//!   single-use, and each confirmation is notified;
//! - IDV-gated: an unsigned / wrong-key / wrong-alg / replayed / cross-case / FAIL callback
//!   does NOT complete recovery; only a valid signed single-use case-bound PASS callback does,
//!   driven end to end by an in-repo fixture provider;
//! - flag off: every advanced-recovery entry point is inert and every route answers a 404.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::Harness;
use ironauth_config::{AdvancedRecoveryConfig, IdvProvider, OidcConfig};
use ironauth_jose::{EmissionOptions, JwkSet, SigningKey, sign_jws};
use ironauth_oidc::advanced_recovery::{
    finalize_recovery, initiate_admin_approved, initiate_idv, initiate_trusted_contact,
};
use ironauth_oidc::recovery::gate_factor_removal;
use ironauth_oidc::{
    FactorChangeDecision, RecoveryFactor, RiskDirective, RiskEvaluator, RiskEvent,
    VerificationPurpose, VerificationSender,
};
use ironauth_store::{ActorRef, CorrelationId, RecoveryEntryPoint, ServiceId, UserId};
use serde_json::json;

const IDV_ISS: &str = "https://idv.example";
const IDV_SLUG: &str = "fixture";
const IDV_KID: &str = "idv-key-1";
/// A second provider whose allowlist is `ES256`-only, to drive the wrong-algorithm rejection
/// (a callback signed `EdDSA`, whose alg is outside the allowlist, is rejected).
const STRICT_ISS: &str = "https://idv-strict.example";
const STRICT_SLUG: &str = "strictalg";

/// A force-delay recovery risk evaluator: every recovery is HELD with `hold_until`, so the
/// tests exercise the #81 delay gate on every mode.
#[derive(Debug)]
struct ForceDelay;

impl RiskEvaluator for ForceDelay {
    fn evaluate_recovery(&self, _event: &RiskEvent<'_>) -> RiskDirective {
        RiskDirective::ForceDelay
    }
}

/// A recording verification sender: captures every recovery notification recipient.
#[derive(Debug, Default)]
struct RecordingSender {
    notified: Mutex<Vec<String>>,
}

impl RecordingSender {
    fn recipients(&self) -> Vec<String> {
        self.notified.lock().expect("lock").clone()
    }
}

impl VerificationSender for RecordingSender {
    fn send(&self, _scope: ironauth_store::Scope, purpose: VerificationPurpose, recipient: &str) {
        if purpose == VerificationPurpose::Recovery {
            self.notified
                .lock()
                .expect("lock")
                .push(recipient.to_owned());
        }
    }
}

fn idv_key(seed: u8, kid: &str) -> SigningKey {
    SigningKey::ed25519_from_seed(Some(kid.to_owned()), &[seed; 32]).expect("ed25519 from seed")
}

fn jwks_of(key: &SigningKey) -> String {
    JwkSet::from_signing_keys(std::iter::once(key))
        .expect("jwks")
        .to_json()
        .expect("jwks json")
}

/// A config that arms all three advanced-recovery modes, with a SHORT recovery delay so a
/// test can advance the clock past the held window, `required_confirmations` = 2, and the
/// fixture (`EdDSA`) plus a strict (`ES256`-only) IDV provider registered against `key`'s JWKS.
fn advanced_config(key: &SigningKey) -> OidcConfig {
    let jwks = jwks_of(key);
    OidcConfig {
        require_pkce_for_confidential_clients: false,
        recovery_delay_secs: 2,
        recovery_cooldown_secs: 1,
        advanced_recovery: AdvancedRecoveryConfig {
            admin_approved_enabled: true,
            trusted_contact_enabled: true,
            idv_enabled: true,
            required_confirmations: 2,
            idv_providers: vec![
                IdvProvider {
                    slug: IDV_SLUG.to_owned(),
                    enabled: true,
                    redirect_url: "https://idv.example/verify".to_owned(),
                    jwks: jwks.clone(),
                    algorithms: vec!["EdDSA".to_owned()],
                    iss: IDV_ISS.to_owned(),
                    session_ttl_secs: 900,
                },
                IdvProvider {
                    slug: STRICT_SLUG.to_owned(),
                    enabled: true,
                    redirect_url: "https://idv-strict.example/verify".to_owned(),
                    jwks,
                    algorithms: vec!["ES256".to_owned()],
                    iss: STRICT_ISS.to_owned(),
                    session_ttl_secs: 900,
                },
            ],
        },
        ..OidcConfig::default()
    }
}

fn service_actor(harness: &Harness) -> ActorRef {
    ActorRef::service(ServiceId::generate(harness.env()))
}

async fn seed_subject(harness: &Harness) -> UserId {
    let raw = harness.seed_unique_user().await;
    UserId::parse_in_scope(&raw, &harness.scope()).expect("seed subject parses")
}

/// The recovery flow's state-machine position, read directly.
async fn flow_state(harness: &Harness, flow_id: &str) -> String {
    sqlx::query_scalar("SELECT state FROM recovery_flows WHERE id = $1")
        .bind(flow_id)
        .fetch_one(harness.db().owner_pool())
        .await
        .expect("flow state")
}

async fn idv_consumed(harness: &Harness, flow_id: &str) -> (bool, Option<String>) {
    let row: (bool, Option<String>) = sqlx::query_as(
        "SELECT (consumed_at IS NOT NULL) AS consumed, verdict \
         FROM recovery_idv_sessions WHERE flow_id = $1",
    )
    .bind(flow_id)
    .fetch_one(harness.db().owner_pool())
    .await
    .expect("idv session");
    (row.0, row.1)
}

/// POST a body to the scope-routed IDV callback route and return the status.
async fn post_idv_callback(harness: &Harness, body: String) -> StatusCode {
    let scope = harness.scope();
    let uri = format!(
        "/t/{}/e/{}/recover/idv/callback",
        scope.tenant(),
        scope.environment()
    );
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/jwt")
        .body(Body::from(body))
        .expect("request");
    harness.send(request).await.0
}

/// Sign an IDV callback JWS with `key`, echoing the case binding and asserting `result`.
#[allow(clippy::too_many_arguments)]
fn signed_callback(
    key: &SigningKey,
    iss: &str,
    aud: &str,
    now_secs: i64,
    flow: &str,
    state: &str,
    nonce: &str,
    result: &str,
) -> String {
    let claims = json!({
        "iss": iss,
        "aud": aud,
        "iat": now_secs,
        "exp": now_secs + 600,
        "flow": flow,
        "state": state,
        "nonce": nonce,
        "result": result,
    });
    let payload = serde_json::to_vec(&claims).expect("claims serialize");
    sign_jws(key, &payload, &EmissionOptions::new()).expect("sign the callback")
}

fn now_secs(harness: &Harness) -> i64 {
    i64::try_from(
        ironauth_env::Clock::now_utc(harness.env().clock())
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after epoch")
            .as_secs(),
    )
    .expect("fits i64")
}

// ---------------------------------------------------------------------------
// Flag off: every mode is inert and every route answers a 404.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn flag_off_all_modes_are_inert_and_routes_404() {
    // A default store-backed harness has the advanced-recovery feature OFF.
    let harness = Harness::start_store_backed().await;
    let subject = seed_subject(&harness).await;
    let scope = harness.scope();

    assert!(
        initiate_admin_approved(
            harness.state(),
            scope,
            &subject,
            RecoveryEntryPoint::LostAllFactors,
            RecoveryFactor::EmailOtp,
            "u@example.test",
            None,
        )
        .await
        .is_none(),
        "admin-approved initiation is inert with the flag off"
    );
    assert!(
        initiate_trusted_contact(
            harness.state(),
            scope,
            &subject,
            RecoveryEntryPoint::LostAllFactors,
            RecoveryFactor::EmailOtp,
            "u@example.test",
            None,
        )
        .await
        .is_none(),
        "trusted-contact initiation is inert with the flag off"
    );
    assert!(
        initiate_idv(
            harness.state(),
            scope,
            &subject,
            RecoveryEntryPoint::LostAllFactors,
            RecoveryFactor::EmailOtp,
            "u@example.test",
            None,
            IDV_SLUG,
        )
        .await
        .is_none(),
        "idv initiation is inert with the flag off"
    );

    // Both data-plane routes answer a uniform 404 with the flag off.
    assert_eq!(
        post_idv_callback(&harness, "not-a-jws".to_owned()).await,
        StatusCode::NOT_FOUND
    );
    let scope = harness.scope();
    let confirm_uri = format!(
        "/t/{}/e/{}/recover/trusted-contact/confirm",
        scope.tenant(),
        scope.environment()
    );
    let request = Request::builder()
        .method("POST")
        .uri(confirm_uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from("token=whatever"))
        .expect("request");
    assert_eq!(harness.send(request).await.0, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// The downgrade invariant still guards a factor removal under an advanced mode.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_mode_never_bypasses_the_downgrade_invariant() {
    let key = idv_key(1, IDV_KID);
    let mut harness = Harness::start_store_backed().await;
    harness.enable_advanced_recovery(
        &advanced_config(&key),
        Arc::new(ForceDelay),
        Arc::new(RecordingSender::default()),
    );
    let subject = seed_subject(&harness).await;
    let scope = harness.scope();

    // An admin-approved recovery via email OTP (pwd) is created HELD.
    let flow = initiate_admin_approved(
        harness.state(),
        scope,
        &subject,
        RecoveryEntryPoint::LostAllFactors,
        RecoveryFactor::EmailOtp,
        "u@example.test",
        None,
    )
    .await
    .expect("admin-approved flow created");
    assert_eq!(flow_state(&harness, &flow.to_string()).await, "held");

    // While the flow is held, removing a STRONGER factor (a passkey, phr) is BLOCKED by the
    // downgrade invariant: a recovery mode can never remove a stronger factor faster than the
    // delay / re-verify rules allow.
    let decision = gate_factor_removal(
        harness.state(),
        scope,
        &subject,
        RecoveryFactor::Passkey,
        None,
    )
    .await;
    assert_eq!(
        decision,
        FactorChangeDecision::Blocked,
        "a stronger-factor removal is blocked while the recovery is held"
    );

    // Once the delay window elapses (every channel notified), the removal is permitted by the
    // delay branch, exactly as #81 allows -- the mode never changed this rule.
    harness.clock().advance(Duration::from_secs(3));
    let decision = gate_factor_removal(
        harness.state(),
        scope,
        &subject,
        RecoveryFactor::Passkey,
        None,
    )
    .await;
    assert_eq!(decision, FactorChangeDecision::AllowedByDelay);
}

// ---------------------------------------------------------------------------
// Admin-approved: lands in the queue, completes THROUGH the delay gate, approver audited.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_approved_lands_in_the_admin_queue_held() {
    // The control-plane approve + completion-through-the-delay-gate + approver audit is
    // exercised over the real management HTTP surface in the ironauth-admin crate's
    // recovery_approvals integration test (only the control role holds the approve grant). Here
    // the data-plane initiation is proven to land the case HELD with method=admin_approved and
    // a pending approval row (the queue landing).
    let key = idv_key(1, IDV_KID);
    let mut harness = Harness::start_store_backed().await;
    harness.enable_advanced_recovery(
        &advanced_config(&key),
        Arc::new(ForceDelay),
        Arc::new(RecordingSender::default()),
    );
    let subject = seed_subject(&harness).await;
    let scope = harness.scope();

    let flow = initiate_admin_approved(
        harness.state(),
        scope,
        &subject,
        RecoveryEntryPoint::LostAllFactors,
        RecoveryFactor::EmailOtp,
        "u@example.test",
        None,
    )
    .await
    .expect("flow created");
    assert_eq!(flow_state(&harness, &flow.to_string()).await, "held");
    let method: String = sqlx::query_scalar("SELECT method FROM recovery_flows WHERE id = $1")
        .bind(flow.to_string())
        .fetch_one(harness.db().owner_pool())
        .await
        .expect("method");
    assert_eq!(method, "admin_approved");
    let pending: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM recovery_approvals WHERE flow_id = $1 AND state = 'pending'",
    )
    .bind(flow.to_string())
    .fetch_one(harness.db().owner_pool())
    .await
    .expect("pending count");
    assert_eq!(pending, 1, "a pending admin approval was opened");
}

// ---------------------------------------------------------------------------
// Trusted-contact: distinct-contact threshold, single-use tokens, notified, delay gate.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn trusted_contact_requires_distinct_confirmations_and_honors_the_delay() {
    let key = idv_key(1, IDV_KID);
    let mut harness = Harness::start_store_backed().await;
    let sender = Arc::new(RecordingSender::default());
    harness.enable_advanced_recovery(&advanced_config(&key), Arc::new(ForceDelay), sender.clone());
    let subject = seed_subject(&harness).await;
    let scope = harness.scope();

    // Designate TWO trusted contacts (required_confirmations = 2).
    let actor = service_actor(&harness);
    for address in ["alice@contact.test", "bob@contact.test"] {
        harness
            .store()
            .scoped(scope)
            .acting(actor, CorrelationId::generate(harness.env()))
            .recovery_trusted_contacts()
            .enroll(harness.env(), &subject, address)
            .await
            .expect("enroll contact");
    }

    let init = initiate_trusted_contact(
        harness.state(),
        scope,
        &subject,
        RecoveryEntryPoint::LostAllFactors,
        RecoveryFactor::EmailOtp,
        "u@example.test",
        None,
    )
    .await
    .expect("trusted-contact flow created");
    assert_eq!(
        init.tokens.len(),
        2,
        "one confirmation token per designated contact"
    );
    // Both designated contacts were notified out of band.
    let notified = sender.recipients();
    assert!(notified.contains(&"alice@contact.test".to_owned()));
    assert!(notified.contains(&"bob@contact.test".to_owned()));

    let confirm = |token: String| {
        let harness = &harness;
        async move {
            ironauth_oidc::advanced_recovery::consume_trusted_contact_confirmation(
                harness.state(),
                scope,
                &token,
            )
            .await
        }
    };

    // One confirmation is not enough for a threshold of two.
    assert!(!confirm(init.tokens[0].clone()).await);
    assert_eq!(
        flow_state(&harness, &init.flow_id.to_string()).await,
        "held"
    );

    // The SAME contact confirming twice is a single-use no-op: it does NOT reach a threshold
    // of two.
    assert!(!confirm(init.tokens[0].clone()).await);
    let confirmed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM recovery_contact_confirmations WHERE flow_id = $1 \
         AND confirmed_at IS NOT NULL",
    )
    .bind(init.flow_id.to_string())
    .fetch_one(harness.db().owner_pool())
    .await
    .expect("confirmed count");
    assert_eq!(
        confirmed, 1,
        "a single contact confirming twice counts once"
    );

    // The SECOND distinct contact confirms: the threshold is now met, BUT the delay window has
    // not elapsed, so the recovery stays HELD (the mode never bypasses the delay).
    assert!(!confirm(init.tokens[1].clone()).await);
    assert_eq!(
        flow_state(&harness, &init.flow_id.to_string()).await,
        "held"
    );

    // Once the delay elapses, completion succeeds THROUGH the gate (threshold met + delay
    // served). A hosted "finalize recovery" action calls the completion gate.
    harness.clock().advance(Duration::from_secs(3));
    assert!(finalize_recovery(harness.state(), scope, &init.flow_id).await);
    assert_eq!(
        flow_state(&harness, &init.flow_id.to_string()).await,
        "completed"
    );
}

// ---------------------------------------------------------------------------
// IDV-gated: the fixture provider drives the happy path; every forgery is rejected.
// ---------------------------------------------------------------------------

async fn start_idv_flow(harness: &Harness, key: &SigningKey) -> (String, String, String) {
    let subject = seed_subject(harness).await;
    let scope = harness.scope();
    let init = initiate_idv(
        harness.state(),
        scope,
        &subject,
        RecoveryEntryPoint::LostAllFactors,
        RecoveryFactor::EmailOtp,
        "u@example.test",
        None,
        IDV_SLUG,
    )
    .await
    .expect("idv flow created");
    let _ = key;
    (
        init.flow_id.to_string(),
        init.state.clone(),
        init.callback_nonce.clone(),
    )
}

#[tokio::test]
async fn idv_happy_path_completes_through_the_gate() {
    let key = idv_key(1, IDV_KID);
    let mut harness = Harness::start_store_backed().await;
    harness.enable_advanced_recovery(
        &advanced_config(&key),
        Arc::new(ForceDelay),
        Arc::new(RecordingSender::default()),
    );
    let (flow, state, nonce) = start_idv_flow(&harness, &key).await;
    let aud = harness.state().issuer_for(&harness.scope());

    // A valid signed PASS callback is verified and consumed; but the delay window has not
    // elapsed, so the recovery stays HELD (the callback never bypasses the delay).
    let callback = signed_callback(
        &key,
        IDV_ISS,
        &aud,
        now_secs(&harness),
        &flow,
        &state,
        &nonce,
        "pass",
    );
    assert_eq!(
        post_idv_callback(&harness, callback).await,
        StatusCode::ACCEPTED
    );
    let (consumed, verdict) = idv_consumed(&harness, &flow).await;
    assert!(consumed, "the callback was consumed single-use");
    assert_eq!(verdict.as_deref(), Some("pass"));
    assert_eq!(
        flow_state(&harness, &flow).await,
        "held",
        "completion waits for the delay"
    );

    // Once the delay elapses, the completion gate finalizes it (method satisfied + delay
    // served).
    harness.clock().advance(Duration::from_secs(3));
    let flow_id = ironauth_store::RecoveryFlowId::parse_in_scope(&flow, &harness.scope()).unwrap();
    assert!(finalize_recovery(harness.state(), harness.scope(), &flow_id).await);
    assert_eq!(flow_state(&harness, &flow).await, "completed");
}

#[tokio::test]
async fn idv_forged_callbacks_never_complete_recovery() {
    let key = idv_key(1, IDV_KID);
    let wrong_key = idv_key(9, IDV_KID);
    let mut harness = Harness::start_store_backed().await;
    harness.enable_advanced_recovery(
        &advanced_config(&key),
        Arc::new(ForceDelay),
        Arc::new(RecordingSender::default()),
    );
    let aud = harness.state().issuer_for(&harness.scope());
    let ts = now_secs(&harness);

    // 1. Unsigned / malformed body: rejected, nothing consumed.
    let (flow, _s, _n) = start_idv_flow(&harness, &key).await;
    assert_eq!(
        post_idv_callback(&harness, "not-a-jws".to_owned()).await,
        StatusCode::BAD_REQUEST
    );
    assert!(!idv_consumed(&harness, &flow).await.0);

    // 2. Wrong key: a valid-shaped callback signed by an UNREGISTERED key is rejected.
    let (flow, state, nonce) = start_idv_flow(&harness, &key).await;
    let forged = signed_callback(&wrong_key, IDV_ISS, &aud, ts, &flow, &state, &nonce, "pass");
    assert_eq!(
        post_idv_callback(&harness, forged).await,
        StatusCode::BAD_REQUEST
    );
    assert!(!idv_consumed(&harness, &flow).await.0);

    // 3. Wrong algorithm: an EdDSA callback claiming the strict (ES256-only) provider's iss is
    //    rejected -- its alg is outside that provider's allowlist.
    let (flow, state, nonce) = start_idv_flow(&harness, &key).await;
    let wrong_alg = signed_callback(&key, STRICT_ISS, &aud, ts, &flow, &state, &nonce, "pass");
    assert_eq!(
        post_idv_callback(&harness, wrong_alg).await,
        StatusCode::BAD_REQUEST
    );
    assert!(!idv_consumed(&harness, &flow).await.0);

    // 4. Cross-case: a callback for flow B carrying flow A's state cannot complete flow B.
    let (flow_a, state_a, _nonce_a) = start_idv_flow(&harness, &key).await;
    let (flow_b, _state_b, nonce_b) = start_idv_flow(&harness, &key).await;
    let cross = signed_callback(&key, IDV_ISS, &aud, ts, &flow_b, &state_a, &nonce_b, "pass");
    assert_eq!(
        post_idv_callback(&harness, cross).await,
        StatusCode::BAD_REQUEST
    );
    assert!(!idv_consumed(&harness, &flow_b).await.0);
    assert!(!idv_consumed(&harness, &flow_a).await.0);

    // 5. FAIL result: a valid signed callback with a FAIL verdict is consumed (recorded) but
    //    NEVER completes the recovery.
    let (flow, state, nonce) = start_idv_flow(&harness, &key).await;
    let fail = signed_callback(&key, IDV_ISS, &aud, ts, &flow, &state, &nonce, "fail");
    assert_eq!(
        post_idv_callback(&harness, fail).await,
        StatusCode::ACCEPTED
    );
    let (consumed, verdict) = idv_consumed(&harness, &flow).await;
    assert!(consumed);
    assert_eq!(verdict.as_deref(), Some("fail"));
    harness.clock().advance(Duration::from_secs(3));
    let flow_id = ironauth_store::RecoveryFlowId::parse_in_scope(&flow, &harness.scope()).unwrap();
    assert!(
        !finalize_recovery(harness.state(), harness.scope(), &flow_id).await,
        "a FAIL callback never completes the recovery"
    );
    assert_eq!(flow_state(&harness, &flow).await, "held");

    // 6. Replay: a valid PASS callback consumed once cannot be replayed (single-use latch).
    let (flow, state, nonce) = start_idv_flow(&harness, &key).await;
    let good = signed_callback(
        &key,
        IDV_ISS,
        &aud,
        now_secs(&harness),
        &flow,
        &state,
        &nonce,
        "pass",
    );
    assert_eq!(
        post_idv_callback(&harness, good.clone()).await,
        StatusCode::ACCEPTED
    );
    assert!(idv_consumed(&harness, &flow).await.0);
    assert_eq!(
        post_idv_callback(&harness, good).await,
        StatusCode::BAD_REQUEST,
        "a replayed callback is rejected"
    );
}
