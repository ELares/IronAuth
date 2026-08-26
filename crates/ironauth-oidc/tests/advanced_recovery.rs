// SPDX-License-Identifier: MIT OR Apache-2.0

//! Advanced recovery modes (issues #82 PR 3 and #295), against a real Postgres with an
//! injected clock.
//!
//! # Part one, the LIBRARY seams (issue #82, PR 3)
//!
//! These pin the acceptance-critical, CI-permanent negatives of the mode machinery:
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
//!
//! # Part two, the HOSTED surface (issue #295)
//!
//! The mounted endpoints, driven over HTTP with a REAL email-OTP proof rather than a
//! fabricated one, because "a handler cannot name a rung" is only demonstrated by the road
//! that has no place to name one:
//!
//! - the crux: a hosted initiation DERIVES `recover_acr` from the evidence, on BOTH arms of
//!   the proof, so no body shape inflates it and the case is HELD;
//! - the delay that buys: the hosted finalize mints no session before the method precondition
//!   AND the `hold_until` horizon, including for a `Standard`-method flow, which no mode can
//!   ever satisfy;
//! - the AUDIT-AND-NOTIFY arm SURVIVES the completion: a passkey removal in the window after
//!   a recovered session still writes `recovery.factor_change` and still alerts every channel,
//!   which is the property mounting a finalize would otherwise have destroyed;
//! - uniform refusal in BOTH phases, pre-proof and post-proof, byte-compared;
//! - the flag-off 404, and the email-OTP toggle, which is the sole gate on the proof path.
//!
//! Only the two modes that can COMPLETE are mounted. The trusted-contact initiation and a
//! contact-enrollment surface are absent on purpose (the notification seam carries no link, so
//! a designated contact can never receive a confirmation token); its library seams are still
//! covered by part one.

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
use ironauth_oidc::recovery::{RecoveryInitiation, gate_factor_removal, initiate_recovery};
use ironauth_oidc::{
    FactorChangeDecision, ProvenFactor, RecoveryFactor, RiskDirective, RiskEvaluator, RiskEvent,
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

#[async_trait::async_trait]
impl VerificationSender for RecordingSender {
    async fn send(
        &self,
        _scope: ironauth_store::Scope,
        purpose: VerificationPurpose,
        recipient: &str,
    ) {
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

/// Fabricate the SERVER-DERIVED recovery proof the LIBRARY-seam cases here drive (issue #295).
///
/// The three `initiate_*` seams no longer take a bare [`RecoveryFactor`]; they take a
/// [`ProvenFactor`] with private fields whose production mints all hard-code the `pwd` rung.
/// The library-seam cases below are testing the MODE machinery, not the proof, so they mint
/// through the `testing`-only constructor. The HOSTED cases at the bottom of this file take
/// the other road and drive a REAL email-OTP proof through the mounted endpoints, which is
/// what pins that a handler cannot name a rung at all.
fn proof(harness: &Harness, subject: &UserId, factor: RecoveryFactor) -> ProvenFactor {
    ProvenFactor::fabricated_for_tests(harness.scope(), *subject, factor)
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

    assert!(
        initiate_admin_approved(
            harness.state(),
            &proof(&harness, &subject, RecoveryFactor::EmailOtp),
            RecoveryEntryPoint::LostAllFactors,
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
            &proof(&harness, &subject, RecoveryFactor::EmailOtp),
            RecoveryEntryPoint::LostAllFactors,
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
            &proof(&harness, &subject, RecoveryFactor::EmailOtp),
            RecoveryEntryPoint::LostAllFactors,
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
        &proof(&harness, &subject, RecoveryFactor::EmailOtp),
        RecoveryEntryPoint::LostAllFactors,
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

    let flow = initiate_admin_approved(
        harness.state(),
        &proof(&harness, &subject, RecoveryFactor::EmailOtp),
        RecoveryEntryPoint::LostAllFactors,
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
        &proof(&harness, &subject, RecoveryFactor::EmailOtp),
        RecoveryEntryPoint::LostAllFactors,
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
    let init = initiate_idv(
        harness.state(),
        &proof(harness, &subject, RecoveryFactor::EmailOtp),
        RecoveryEntryPoint::LostAllFactors,
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

// ===========================================================================================
// THE HOSTED FLOW (issue #295): the mounted initiation, finalization, and enrollment surface.
// ===========================================================================================

/// A recording sender that captures BOTH the recovery notification recipients and the
/// DELIVERED email-OTP codes, so a hosted test can drive the real proof the initiation
/// endpoints demand rather than fabricating one.
#[derive(Debug, Default)]
struct HostedSender {
    notified: Mutex<Vec<String>>,
    codes: Mutex<Vec<(String, String)>>,
}

impl HostedSender {
    fn recipients(&self) -> Vec<String> {
        self.notified.lock().expect("lock").clone()
    }

    /// The LAST code delivered to `recipient` (each send invalidates its predecessor).
    fn last_code(&self, recipient: &str) -> String {
        self.codes
            .lock()
            .expect("lock")
            .iter()
            .rev()
            .find(|(to, _)| to == recipient)
            .map(|(_, code)| code.clone())
            .expect("a recovery code was delivered")
    }
}

#[async_trait::async_trait]
impl VerificationSender for HostedSender {
    async fn send(
        &self,
        _scope: ironauth_store::Scope,
        purpose: VerificationPurpose,
        recipient: &str,
    ) {
        if purpose == VerificationPurpose::Recovery {
            self.notified
                .lock()
                .expect("lock")
                .push(recipient.to_owned());
        }
    }

    fn deliver_email_otp(&self, message: &ironauth_oidc::EmailOtpMessage<'_>) {
        self.codes
            .lock()
            .expect("lock")
            .push((message.recipient.to_owned(), message.code.to_owned()));
    }
}

/// The scope-routed base path of the harness environment.
fn base(harness: &Harness) -> String {
    let scope = harness.scope();
    format!("/t/{}/e/{}", scope.tenant(), scope.environment())
}

/// POST a JSON body and return the status, the headers, and the parsed body.
async fn post_json(
    harness: &Harness,
    path: &str,
    body: &serde_json::Value,
    cookie: Option<&str>,
    origin: Option<&str>,
) -> (StatusCode, header::HeaderMap, serde_json::Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    if let Some(origin) = origin {
        builder = builder.header(header::ORIGIN, origin);
    }
    let (status, headers, raw) = harness
        .send(
            builder
                .body(Body::from(body.to_string()))
                .expect("request builds"),
        )
        .await;
    let parsed = serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null);
    (status, headers, parsed)
}

/// Arm the hosted surface: the three modes on, a SHORT delay, and a recording sender that
/// captures both the notifications and the delivered one-time codes.
///
/// The risk evaluator is the NULL one, deliberately, and that is load bearing. The
/// library-seam cases above install [`ForceDelay`] so every flow is held whatever its rung;
/// here the hold must come from the RUNG ALONE, because "an inflated factor would skip
/// `hold_until`" is the claim under test and a forced delay would hide exactly that. With the
/// null evaluator a case is held if and only if `reduces_security` says so.
///
/// The escalating #64 throttle runs at its PRODUCTION DEFAULT here, and that is deliberate.
///
/// An earlier draft raised `soft_threshold` from 5 to 1000, because each hosted step
/// legitimately spends two recovery-path attempts (the code send and the code verify) and a
/// multi-step case therefore walked straight into the escalating delay. That was a harness
/// workaround for a real defect rather than a test-fixture need: `prove_email_otp` was the one
/// consumer of the email-OTP verify core that discarded the abuse context, so a code that
/// MATCHED never relaxed the counters the way every other consumer's does. A real user at
/// defaults spent four attempts on the happy path with no relaxation and one mistyped code
/// pushed them over.
///
/// It now calls `reset_after_success` on both proof arms, so a proven code relaxes the
/// counters and every case in this file runs at the shipped default. The uniformity case is
/// the one that deliberately spends failures, and it takes a FRESH identifier for the
/// post-proof phase rather than a raised threshold, so a throttled verify (which answers the
/// same refusal) can never be what makes those assertions pass.
async fn hosted_harness(key: &SigningKey) -> (Harness, Arc<HostedSender>) {
    let mut harness = Harness::start_store_backed().await;
    let sender = Arc::new(HostedSender::default());
    harness.enable_advanced_recovery(
        &advanced_config(key),
        Arc::new(ironauth_oidc::NullRiskEvaluator),
        sender.clone(),
    );
    (harness, sender)
}

/// Request a RECOVERY-purpose email one-time code over the public send endpoint and return
/// the code the transport seam delivered. This is the real evidence the initiation endpoints
/// verify; no test path can hand them a factor directly.
async fn recovery_code(harness: &Harness, sender: &HostedSender, identifier: &str) -> String {
    let (status, _headers, _body) = post_json(
        harness,
        &format!("{}/otp/send", base(harness)),
        &json!({ "identifier": identifier, "purpose": "recovery" }),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the recovery code send is accepted");
    sender.last_code(identifier)
}

/// The recovery flow's stored `recover_acr`: the value that decides whether the case is HELD.
async fn flow_recover_acr(harness: &Harness, flow_id: &str) -> String {
    sqlx::query_scalar("SELECT recover_acr FROM recovery_flows WHERE id = $1")
        .bind(flow_id)
        .fetch_one(harness.db().owner_pool())
        .await
        .expect("recover_acr")
}

/// The one pending recovery flow for a subject, as (id, state, `recover_acr`).
async fn only_flow(harness: &Harness, subject: &str) -> (String, String, String) {
    let row: (String, String, String) = sqlx::query_as(
        "SELECT id, state, recover_acr FROM recovery_flows WHERE subject = $1 ORDER BY id",
    )
    .bind(subject)
    .fetch_one(harness.db().owner_pool())
    .await
    .expect("exactly one recovery flow");
    row
}

/// Seed a user whose account is protected by a SYNCED PASSKEY (`phr`), the posture that makes
/// an inflated `pwd` claim worth something to an attacker.
async fn seed_passkey_user(harness: &Harness, identifier: &str) -> (String, UserId) {
    let subject = harness
        .seed_user(identifier, "correct horse battery staple")
        .await;
    harness.seed_passkey(&subject, true).await;
    let typed = UserId::parse_in_scope(&subject, &harness.scope()).expect("subject parses");
    (subject, typed)
}

/// Whether a response set the session cookie.
fn sets_session_cookie(headers: &header::HeaderMap) -> bool {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| value.starts_with(ironauth_oidc::SESSION_COOKIE))
}

/// The `name=value` cookie pair a response's `Set-Cookie` established, ready to send back as a
/// `Cookie` header. This is how a test holds the RECOVERED session rather than a synthesized
/// one: the capability under examination is the one the endpoint actually handed out.
fn session_cookie_from(headers: &header::HeaderMap) -> Option<String> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with(ironauth_oidc::SESSION_COOKIE))
        .map(|value| value.split(';').next().unwrap_or(value).to_owned())
}

/// Register an additional VERIFIED phone channel for `subject`, so a test can count the
/// out-of-band alerts `notify_all_channels` sends WITHOUT counting the one-time codes the
/// harness itself keeps requesting on the email channel.
async fn add_verified_phone(harness: &Harness, subject: &UserId, raw: &str) {
    harness
        .store()
        .scoped(harness.scope())
        .acting(
            harness.db().test_actor(harness.env()),
            CorrelationId::generate(harness.env()),
        )
        .user_identifiers()
        .add(
            harness.env(),
            ironauth_store::NewUserIdentifier {
                id: &ironauth_store::UserIdentifierId::generate(harness.env(), &harness.scope()),
                user_id: subject,
                identifier_type: ironauth_store::IdentifierType::Phone,
                raw,
                verified: true,
                mode: ironauth_store::UniquenessMode::EnvironmentWide,
                org: None,
            },
            None,
        )
        .await
        .expect("add verified phone");
}

/// How many recovery alerts the send seam has delivered to `recipient` so far.
fn alerts_to(sender: &HostedSender, recipient: &str) -> usize {
    sender
        .recipients()
        .iter()
        .filter(|to| to.as_str() == recipient)
        .count()
}

/// The `pky_` ids of `subject`'s registered passkeys.
async fn passkey_ids(harness: &Harness, subject: &UserId) -> Vec<String> {
    harness
        .store()
        .scoped(harness.scope())
        .webauthn_credentials()
        .list(subject, 10, None)
        .await
        .expect("list passkeys")
        .into_iter()
        .map(|record| record.id)
        .collect()
}

/// The `detail` strings of every `recovery.factor_change` audit row in the harness scope, so a
/// test can prove the downgrade decision was RECORDED and not merely taken.
async fn factor_change_details(harness: &Harness) -> Vec<String> {
    let scope = harness.scope();
    sqlx::query_scalar(
        "SELECT detail FROM audit_log \
         WHERE tenant_id = $1 AND environment_id = $2 AND action = 'recovery.factor_change' \
         AND detail IS NOT NULL ORDER BY occurred_at, id",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_all(harness.db().owner_pool())
    .await
    .expect("read factor_change audit")
}

// -------------------------------------------------------------------------------------------
// THE crux: a hosted initiation CANNOT inflate the recover factor.
// -------------------------------------------------------------------------------------------

/// The hosted initiation derives `recover_acr` from the evidence it verified, so a client that
/// tries every shape of inflation still gets the `pwd` rung and a HELD case.
///
/// This is the whole point of issue #295. The account here holds a synced passkey (`phr`). If
/// the endpoint took the client's word for the factor, a body claiming an attested passkey
/// would make `reduces_security = false`, leave `hold_until` NULL, and let the case complete
/// the instant the mode was satisfied, with no delay and no cancellation window.
///
/// The three assertions are deliberately different claims: the stored rung is the `pwd` floor
/// (the derivation), the state is `held` (the delay was applied), and `hold_until` is actually
/// SET (the delay is a real horizon, not a label). A regression that dropped only the last one
/// would still pass the first two.
#[tokio::test]
async fn a_hosted_initiation_cannot_inflate_the_recover_factor() {
    let key = idv_key(1, IDV_KID);
    let (harness, sender) = hosted_harness(&key).await;
    let identifier = "inflate@example.test";
    let (subject, _typed) = seed_passkey_user(&harness, identifier).await;
    let code = recovery_code(&harness, &sender, identifier).await;

    // Every inflation shape a client could reach for, in one body: a recover_factor field, an
    // acr field, and a subject field. None of them is a field of `InitiateBody`, and none of
    // them can become one without an argument position existing on the initiation seam to
    // carry it, which is what `ProvenFactor` removes.
    let (status, _headers, body) = post_json(
        &harness,
        &format!("{}/recover/admin-approved/initiate", base(&harness)),
        &json!({
            "identifier": identifier,
            "code": code,
            "recover_factor": "AttestedPasskey",
            "recover_acr": "urn:ironauth:acr:attested_passkey",
            "factor": "attested_passkey",
            "subject": "usr_someone_else",
        }),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the initiation succeeded: {body:?}");

    let (flow_id, state, recover_acr) = only_flow(&harness, &subject).await;
    assert_eq!(
        recover_acr,
        RecoveryFactor::EmailOtp.strength_acr(),
        "the stored recover_acr is the SERVER-DERIVED pwd rung, not the claimed one"
    );
    assert_eq!(
        state, "held",
        "a pwd-rung recovery against a passkey account is HELD; an inflated rung would not be"
    );
    let held_until_set: bool =
        sqlx::query_scalar("SELECT (hold_until IS NOT NULL) FROM recovery_flows WHERE id = $1")
            .bind(&flow_id)
            .fetch_one(harness.db().owner_pool())
            .await
            .expect("hold_until");
    assert!(
        held_until_set,
        "the delay horizon is actually set, not merely labelled"
    );

    // The SECOND account exercises the OTHER arm of the proof, and the first draft of this test
    // did not, which a mutation found: on a passkey-protected account the issue #267 gate
    // refuses the email OTP a primary session, so the verify core returns `Blocked` and the
    // `Verified` arm above is never reached. This account holds nothing stronger than its
    // password, so the code VERIFIES outright. Both arms must attest the same `pwd` rung.
    //
    // `held` cannot be the discriminator here (a pwd rung against a pwd account is no
    // downgrade, so the case is legitimately NOT held), which is exactly why the stored
    // `recover_acr` is asserted directly: an inflated rung would write `attested_passkey` into
    // a column that must read `pwd`.
    let plain = "plain@example.test";
    let plain_subject = harness
        .seed_user(plain, "correct horse battery staple")
        .await;
    let code = recovery_code(&harness, &sender, plain).await;
    let (status, _headers, body) = post_json(
        &harness,
        &format!("{}/recover/admin-approved/initiate", base(&harness)),
        &json!({
            "identifier": plain,
            "code": code,
            "recover_factor": "AttestedPasskey",
            "recover_acr": "urn:ironauth:acr:attested_passkey",
        }),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    let (_id, state, recover_acr) = only_flow(&harness, &plain_subject).await;
    assert_eq!(
        recover_acr,
        RecoveryFactor::EmailOtp.strength_acr(),
        "the VERIFIED arm attests the same pwd rung the BLOCKED arm does"
    );
    assert_eq!(
        state, "initiated",
        "and a pwd recovery on a pwd-only account is honestly NOT held, so the held assertion          above is discriminating rather than always true"
    );
}

/// The delay the inflation would have skipped is REAL: with the case held, the hosted finalize
/// mints NO session before the horizon and DOES after it.
///
/// This is the other half of the crux. The test above shows the rung cannot be inflated; this
/// one shows what the rung buys, so a future change that made the rung honest but stopped
/// gating on it would still be caught.
#[tokio::test]
async fn a_hosted_finalize_mints_no_session_until_the_method_and_the_delay_are_both_satisfied() {
    let key = idv_key(1, IDV_KID);
    let (harness, sender) = hosted_harness(&key).await;
    let identifier = "gated@example.test";
    let (subject, typed) = seed_passkey_user(&harness, identifier).await;

    let code = recovery_code(&harness, &sender, identifier).await;
    let (status, _headers, _body) = post_json(
        &harness,
        &format!("{}/recover/admin-approved/initiate", base(&harness)),
        &json!({ "identifier": identifier, "code": code }),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (flow_id, state, _acr) = only_flow(&harness, &subject).await;
    assert_eq!(state, "held");
    let flow = ironauth_store::RecoveryFlowId::parse_in_scope(&flow_id, &harness.scope())
        .expect("flow id parses");

    // 1. METHOD UNSATISFIED (no admin approval yet), delay unelapsed: no session.
    let code = recovery_code(&harness, &sender, identifier).await;
    let (status, headers, _body) = post_json(
        &harness,
        &format!("{}/recover/finalize", base(&harness)),
        &json!({ "identifier": identifier, "code": code }),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        !sets_session_cookie(&headers),
        "an unsatisfied method mints no session"
    );

    // 2. METHOD SATISFIED (the admin approved through the control plane) but the recovery is
    //    still inside its delay window: STILL no session. This is the assertion an inflated
    //    recover factor would have made unreachable, because there would have been no window.
    // The control plane approves. Driven at the store rather than over the management API on
    // purpose: only `ironauth_control` holds the UPDATE grant on `recovery_approvals` (issue
    // #82's structural no-self-approval split), and this harness runs as `ironauth_app`. The
    // management-surface path is covered by the admin crate's `recovery_approvals` suite; what
    // this test owns is what the DATA plane does once the method is satisfied.
    sqlx::query("UPDATE recovery_approvals SET state = 'approved' WHERE flow_id = $1")
        .bind(flow.to_string())
        .execute(harness.db().owner_pool())
        .await
        .expect("the control plane approves");
    let (_id, state, _acr) = only_flow(&harness, &subject).await;
    assert_eq!(state, "held", "approval alone does not complete the case");
    // Move the clock, but STAY INSIDE the two second window, so the refusal below is the
    // horizon comparison and not merely a clock that never moved.
    harness.clock().advance(Duration::from_secs(1));
    let code = recovery_code(&harness, &sender, identifier).await;
    let (status, headers, _body) = post_json(
        &harness,
        &format!("{}/recover/finalize", base(&harness)),
        &json!({ "identifier": identifier, "code": code }),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        !sets_session_cookie(&headers),
        "an unelapsed delay window mints no session even with the method satisfied"
    );
    let (_id, state, _acr) = only_flow(&harness, &subject).await;
    assert_eq!(state, "held", "and the case was not completed either");

    // 3. Both satisfied: the session is minted, and only now.
    harness.clock().advance(Duration::from_secs(5));
    let code = recovery_code(&harness, &sender, identifier).await;
    let (status, headers, body) = post_json(
        &harness,
        &format!("{}/recover/finalize", base(&harness)),
        &json!({ "identifier": identifier, "code": code }),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(body["recovered"], json!(true));
    assert_eq!(
        body["amr"],
        json!(["otp"]),
        "the recovered session is an HONEST email-OTP session, never a passkey one"
    );
    assert!(
        sets_session_cookie(&headers),
        "the recovered subject's session is established"
    );
    let (_id, state, _acr) = only_flow(&harness, &subject).await;
    assert_eq!(state, "completed");

    // What the completed case then does to the downgrade gate, stated exactly.
    //
    // The recovered session is `pwd`-strength, so it can never present the fresh
    // equal-or-stronger proof that is `AllowedByReverify`. That is TRUE and it is not what
    // decides this: completing the case ENDS the pending flow the gate keys on, and the delay
    // the gate exists to impose was served before `complete` returned true at all. So the
    // removal is PERMITTED, exactly as it already was once `hold_until` elapsed with the flow
    // still pending. What must not change across the completion is the other arm of that
    // permission, the audit row and the notification, which
    // `a_factor_removal_after_a_hosted_finalize_is_still_audited_and_notified` drives over the
    // real removal route.
    let decision = gate_factor_removal(
        harness.state(),
        harness.scope(),
        &typed,
        RecoveryFactor::Passkey,
        None,
    )
    .await;
    assert_eq!(
        decision,
        FactorChangeDecision::AllowedByDelay,
        "a completed HELD recovery permits the removal by the delay it already served, and \
         says so, rather than falling silently through to NotADowngrade"
    );
}

// -------------------------------------------------------------------------------------------
// THE regression mounting a finalize would otherwise have caused: a SILENT downgrade.
// -------------------------------------------------------------------------------------------

/// A passkey removal in the window after a hosted finalize is still AUDITED and still NOTIFIED.
///
/// This is the property the whole hosted surface could have cost. `gate_factor_removal` keys on
/// a PENDING recovery flow, and completing the case is what ends the pending state, so the
/// moment `/recover/finalize` shipped, the gate went quiet at exactly the instant a recovered
/// session came into existence. Measured against the real routes before the fix: the gate
/// answered `Blocked` while the flow was held and `NotADowngrade` after the finalize, the real
/// `/webauthn/credentials/remove` route answered `200 {"removed":true}`, the victim's synced
/// passkey rows went to zero, and NO `recovery.factor_change` row and NO notification were
/// written. The removal being PERMITTED was never the defect (a delay-elapsed pending flow
/// permits it too). It being SILENT was.
///
/// So this drives the whole thing end to end over HTTP, with the RECOVERED session's own cookie
/// (the exact capability an attacker who ran the recovery would hold), and asserts the three
/// things that must survive the completion: the removal happens, an `allowed_delay`
/// `recovery.factor_change` row exists, and the owner's OTHER channel is alerted.
///
/// The out-of-band channel is a PHONE, deliberately. The email identifier receives the
/// one-time codes this test keeps requesting, so counting notifications on it would be
/// counting the harness's own traffic; the phone is touched by `notify_all_channels` alone.
#[tokio::test]
async fn a_factor_removal_after_a_hosted_finalize_is_still_audited_and_notified() {
    let key = idv_key(1, IDV_KID);
    let (harness, sender) = hosted_harness(&key).await;
    let identifier = "silent@example.test";
    let (subject, typed) = seed_passkey_user(&harness, identifier).await;
    let phone = "+14155550142";
    add_verified_phone(&harness, &typed, phone).await;

    // Open an admin-approved case, approve it, and let the delay window elapse.
    let code = recovery_code(&harness, &sender, identifier).await;
    let (status, _headers, body) = post_json(
        &harness,
        &format!("{}/recover/admin-approved/initiate", base(&harness)),
        &json!({ "identifier": identifier, "code": code }),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    let (flow_id, state, _acr) = only_flow(&harness, &subject).await;
    assert_eq!(state, "held");
    sqlx::query("UPDATE recovery_approvals SET state = 'approved' WHERE flow_id = $1")
        .bind(&flow_id)
        .execute(harness.db().owner_pool())
        .await
        .expect("the control plane approves");
    harness.clock().advance(Duration::from_secs(5));

    let alerts_before_finalize = alerts_to(&sender, phone);
    let code = recovery_code(&harness, &sender, identifier).await;
    let (status, headers, body) = post_json(
        &harness,
        &format!("{}/recover/finalize", base(&harness)),
        &json!({ "identifier": identifier, "code": code }),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    let recovered_cookie = session_cookie_from(&headers).expect("the recovered session cookie");
    assert_eq!(only_flow(&harness, &subject).await.1, "completed");
    // The completion itself announces the recovered access. Dropping that call used to change
    // nothing any assertion could see.
    let alerts_after_finalize = alerts_to(&sender, phone);
    assert!(
        alerts_after_finalize > alerts_before_finalize,
        "the finalize must alert the owner's other channels that access was recovered \
         ({alerts_before_finalize} -> {alerts_after_finalize})"
    );

    // Now the recovered session removes the passkey, over the REAL route.
    let pky = passkey_ids(&harness, &typed).await;
    let pky = pky.first().expect("the seeded passkey").clone();
    let origin = harness.state().self_origin().expect("a self origin");
    let (status, _headers, body) = post_json(
        &harness,
        &format!("{}/webauthn/credentials/remove", base(&harness)),
        &json!({ "credentialId": pky }),
        Some(&recovered_cookie),
        Some(&origin),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(body["removed"], json!(true));
    assert!(
        passkey_ids(&harness, &typed).await.is_empty(),
        "the removal really happened; this test is about whether it was announced, not \
         whether it was refused"
    );

    // The two things that must have survived the completion.
    let details = factor_change_details(&harness).await;
    assert!(
        details.iter().any(|d| d.contains("decision=allowed_delay")),
        "a recovery.factor_change row must be written for a removal in the post-recovery \
         window, so the downgrade is reconstructable from the log; got {details:?}"
    );
    let alerts_after_removal = alerts_to(&sender, phone);
    assert!(
        alerts_after_removal > alerts_after_finalize,
        "removing a stronger factor after a recovery must alert every channel \
         ({alerts_after_finalize} -> {alerts_after_removal})"
    );
}

/// A recovery that was NEVER HELD imposes no gate once it completes, so the post-recovery
/// window can never lock a user out.
///
/// The window above consults only a HELD flow, and that restriction is the whole safety
/// argument for it: a held flow can only have completed AFTER its `hold_until`, so the
/// decision it yields is `AllowedByDelay` and the window can only ever ADD an audit row and a
/// notification. A flow that was never held has a NULL horizon, which can never satisfy the
/// delay branch, so consulting one would answer `Blocked`.
///
/// The user this protects is ordinary: recover a password-only account (a `pwd` proof against
/// a `pwd` account is no downgrade, so nothing is held), then enrol a passkey, then change
/// your mind. Without the restriction the removal is refused, and refused with no way out,
/// because the recovered session can never present a stronger re-verify either.
#[tokio::test]
async fn a_recovery_that_was_never_held_imposes_no_gate_after_it_completes() {
    let key = idv_key(1, IDV_KID);
    let (harness, sender) = hosted_harness(&key).await;
    let identifier = "unheld@example.test";
    let subject = harness
        .seed_user(identifier, "correct horse battery staple")
        .await;
    let typed = UserId::parse_in_scope(&subject, &harness.scope()).expect("subject parses");

    let code = recovery_code(&harness, &sender, identifier).await;
    let (status, _headers, body) = post_json(
        &harness,
        &format!("{}/recover/admin-approved/initiate", base(&harness)),
        &json!({ "identifier": identifier, "code": code }),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    let (flow_id, state, _acr) = only_flow(&harness, &subject).await;
    assert_eq!(
        state, "initiated",
        "a pwd recovery on a pwd-only account is honestly NOT held, which is the case here"
    );
    sqlx::query("UPDATE recovery_approvals SET state = 'approved' WHERE flow_id = $1")
        .bind(&flow_id)
        .execute(harness.db().owner_pool())
        .await
        .expect("the control plane approves");
    let code = recovery_code(&harness, &sender, identifier).await;
    let (status, _headers, body) = post_json(
        &harness,
        &format!("{}/recover/finalize", base(&harness)),
        &json!({ "identifier": identifier, "code": code }),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(only_flow(&harness, &subject).await.1, "completed");

    // The user now enrols a passkey and removes it. The completed flow was never held, so the
    // post-recovery window must skip it entirely.
    harness.seed_passkey(&subject, true).await;
    let decision = gate_factor_removal(
        harness.state(),
        harness.scope(),
        &typed,
        RecoveryFactor::Passkey,
        None,
    )
    .await;
    assert_eq!(
        decision,
        FactorChangeDecision::NotADowngrade,
        "a completed flow with no delay horizon must NOT be consulted: it can only ever \
         answer Blocked, and would strand a user who enrolled a stronger factor after \
         recovering"
    );
}

// -------------------------------------------------------------------------------------------
// The `Standard` method boundary: no mode, so nothing this gate can ever satisfy.
// -------------------------------------------------------------------------------------------

/// A `Standard`-method flow can NEVER be finalized through the hosted endpoint, however long
/// its delay window has been elapsed.
///
/// `method_satisfied` answers `false` for `RecoveryMethod::Standard`, which reads like a
/// bookkeeping default and is not one: issue #295 mounted the first PUBLIC caller of that
/// function. Every `/recover` and every headless recovery journey creates a `Standard` flow,
/// so if that arm ever answered `true`, an email one-time code alone would finalize one of
/// them into a session with no mode precondition at all, on any account, including a
/// passkey-protected one. Flipping the arm killed NOTHING before this test existed.
#[tokio::test]
async fn a_standard_method_flow_is_never_finalizable_through_the_hosted_endpoint() {
    let key = idv_key(1, IDV_KID);
    let (harness, sender) = hosted_harness(&key).await;
    let identifier = "standard@example.test";
    let (subject, typed) = seed_passkey_user(&harness, identifier).await;

    // A STANDARD flow, exactly what `/recover` and the headless journey create. Driven at the
    // library seam because no hosted endpoint opens one: that is the point, and it is why the
    // hosted finalize must refuse a flow it did not open the mode for.
    let outcome = initiate_recovery(
        harness.state(),
        &proof(&harness, &typed, RecoveryFactor::EmailOtp),
        RecoveryEntryPoint::LostPassword,
        identifier,
        None,
        ironauth_store::RecoveryMethod::Standard,
    )
    .await;
    assert!(
        matches!(outcome, RecoveryInitiation::Created { held: true, .. }),
        "a pwd recovery against a passkey account is held, so the delay is a real horizon"
    );
    let (_id, state, _acr) = only_flow(&harness, &subject).await;
    assert_eq!(state, "held");

    // Well past the horizon: the delay can no longer be what refuses.
    harness.clock().advance(Duration::from_secs(60));
    let code = recovery_code(&harness, &sender, identifier).await;
    let (status, headers, parsed) = post_json(
        &harness,
        &format!("{}/recover/finalize", base(&harness)),
        &json!({ "identifier": identifier, "code": code }),
        None,
        None,
    )
    .await;
    assert_eq!(
        (status, &parsed),
        (
            StatusCode::UNAUTHORIZED,
            &json!({ "error": "recovery_unavailable" })
        ),
        "a Standard flow is not satisfiable through this gate, and refuses uniformly"
    );
    assert!(
        !sets_session_cookie(&headers),
        "and mints no session at all"
    );
    assert_eq!(
        only_flow(&harness, &subject).await.1,
        "held",
        "the flow is still pending: the refusal did not consume the case either"
    );
}

// -------------------------------------------------------------------------------------------
// The email-OTP toggle is the SOLE gate on the proof path.
// -------------------------------------------------------------------------------------------

/// With `oidc.email_otp_enabled` off, every hosted recovery endpoint refuses.
///
/// `prove_email_otp` checks the toggle itself, and that check is not redundant with anything:
/// `verify_email_code` does NOT read it (only the `/otp/send` and `/otp/verify` handlers do),
/// so removing the line would leave the email factor running underneath every hosted recovery
/// endpoint on a deployment that had switched it off.
#[tokio::test]
async fn the_email_otp_toggle_gates_every_hosted_recovery_endpoint() {
    let key = idv_key(1, IDV_KID);
    // A code is issued while the factor is ON, so the refusal below cannot be "no code
    // exists": the presented code is genuinely live for this account.
    let (mut harness, sender) = hosted_harness(&key).await;
    let identifier = "toggle@example.test";
    let _ = harness
        .seed_user(identifier, "correct horse battery staple")
        .await;
    let code = recovery_code(&harness, &sender, identifier).await;

    // Switch the email factor OFF over the SAME store, so the account, its identifier, and the
    // live code above all survive into the refusal.
    let config = OidcConfig {
        email_otp_enabled: false,
        ..advanced_config(&key)
    };
    harness.enable_advanced_recovery(
        &config,
        Arc::new(ironauth_oidc::NullRiskEvaluator),
        sender.clone(),
    );
    for endpoint in [
        "recover/admin-approved/initiate",
        "recover/idv/initiate",
        "recover/finalize",
    ] {
        let (status, headers, parsed) = post_json(
            &harness,
            &format!("{}/{endpoint}", base(&harness)),
            &json!({ "identifier": identifier, "code": code, "provider": IDV_SLUG }),
            None,
            None,
        )
        .await;
        assert_eq!(
            (status, &parsed),
            (
                StatusCode::UNAUTHORIZED,
                &json!({ "error": "recovery_unavailable" })
            ),
            "{endpoint} must refuse while the email factor is off"
        );
        assert!(!sets_session_cookie(&headers));
    }
    let flows: i64 = sqlx::query_scalar("SELECT count(*) FROM recovery_flows")
        .fetch_one(harness.db().owner_pool())
        .await
        .expect("count");
    assert_eq!(flows, 0, "and opens no case");

    // The CONTROL: the same code, the same account, the factor back ON. Without this the
    // assertions above would also pass for a code that had simply expired.
    harness.enable_advanced_recovery(
        &advanced_config(&key),
        Arc::new(ironauth_oidc::NullRiskEvaluator),
        sender.clone(),
    );
    let (status, _headers, body) = post_json(
        &harness,
        &format!("{}/recover/admin-approved/initiate", base(&harness)),
        &json!({ "identifier": identifier, "code": code }),
        None,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the very same code is accepted once the factor is back on: {body:?}"
    );
}

// -------------------------------------------------------------------------------------------
// Uniform refusal: no enumeration oracle on any of the four public endpoints.
// -------------------------------------------------------------------------------------------

/// Every refusal on every hosted endpoint is BYTE-IDENTICAL, whatever the reason.
///
/// The one shape that differs is the feature/mode-off 404, and it differs identically for
/// every tenant and every subject, so it discloses deployment configuration and nothing about
/// an account. The nonexistent-tenant probe is here because this project HAS shipped an
/// existence oracle on a scope-routed public page before.
// One test, one story: the claim is that EVERY refusal on EVERY hosted endpoint is the same
// answer, and it is only worth anything as a single comparison across every reason at once.
// Splitting it into a pre-proof case and a post-proof case would let one of them drift.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn every_hosted_refusal_is_uniform() {
    let key = idv_key(1, IDV_KID);
    let (harness, sender) = hosted_harness(&key).await;
    let identifier = "real@example.test";
    let _ = harness
        .seed_user(identifier, "correct horse battery staple")
        .await;
    let good_code = recovery_code(&harness, &sender, identifier).await;

    let endpoints = [
        "recover/admin-approved/initiate",
        "recover/idv/initiate",
        "recover/finalize",
    ];
    for endpoint in endpoints {
        let path = format!("{}/{endpoint}", base(&harness));
        let mut answers = Vec::new();
        for body in [
            // A KNOWN account with a wrong code.
            json!({ "identifier": identifier, "code": "000000", "provider": IDV_SLUG }),
            // An UNKNOWN account with a plausible code.
            json!({ "identifier": "ghost@example.test", "code": "123456", "provider": IDV_SLUG }),
            // A known account, a code that was never issued for it, and no provider.
            json!({ "identifier": identifier, "code": "999999" }),
            // No identifier at all.
            json!({ "code": "123456" }),
            // No code at all.
            json!({ "identifier": identifier }),
        ] {
            let (status, _headers, parsed) = post_json(&harness, &path, &body, None, None).await;
            answers.push((status, parsed));
        }
        for (status, parsed) in &answers {
            assert_eq!(
                (*status, parsed),
                (
                    StatusCode::UNAUTHORIZED,
                    &json!({ "error": "recovery_unavailable" })
                ),
                "{endpoint} must answer ONE uniform refusal for every reason"
            );
        }
    }

    // A WELL-FORMED but NONEXISTENT scope answers exactly the same refusal as the real one,
    // even when the code presented is a genuinely live one for a real account in another
    // environment. This is the existence-oracle probe: nothing in the answer says whether the
    // tenant is real.
    let ghost_tenant = ironauth_store::TenantId::generate(harness.env());
    let ghost_env = ironauth_store::EnvironmentId::generate(harness.env());
    let ghost_path = format!("/t/{ghost_tenant}/e/{ghost_env}/recover/admin-approved/initiate");
    let (status, _headers, parsed) = post_json(
        &harness,
        &ghost_path,
        &json!({ "identifier": identifier, "code": good_code }),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(parsed, json!({ "error": "recovery_unavailable" }));

    // A MALFORMED scope is the uniform 404 instead. That is a client-side-decidable property
    // of the path, identical for every tenant and every subject, so it enumerates nothing;
    // it is pinned here so the distinction stays deliberate rather than accidental.
    let (status, _headers, _parsed) = post_json(
        &harness,
        "/t/notatenantid/e/notanenvid/recover/admin-approved/initiate",
        &json!({ "identifier": identifier, "code": "123456" }),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // -------------------------------------------------------------------------------------
    // PHASE TWO: the POST-PROOF refusals.
    //
    // Every body above fails inside `prove_email_otp`, so phase one drives exactly one
    // rejection point however many shapes it sends. The reasons the module doc, the CHANGELOG
    // and the checklist rows enumerate mostly live AFTER the proof, and each of them is a
    // different `return` with its own status: the natural failure mode here is a `400 unknown
    // provider` or a `423 account fenced` leaking out beside the `401`, which is exactly the
    // oracle the uniformity claim denies. So each one below is driven with a GOOD code and
    // byte-compared to the SAME answer.
    // -------------------------------------------------------------------------------------
    let refusal = (
        StatusCode::UNAUTHORIZED,
        json!({ "error": "recovery_unavailable" }),
    );

    // (1) An UNKNOWN IDV provider slug, and (2) an ABSENT one, both with a live code.
    //
    // A FRESH identifier, not the one phase one just spent a dozen wrong guesses on: at the
    // production throttle default that account is over its soft threshold, and a throttled
    // verify answers the very same refusal, which would make every assertion below pass
    // without ever reaching the post-proof code these cases exist to drive.
    let prover = "prover@example.test";
    let _ = harness
        .seed_user(prover, "correct horse battery staple")
        .await;
    for provider in [json!("no-such-provider"), json!(null)] {
        let code = recovery_code(&harness, &sender, prover).await;
        let (status, headers, parsed) = post_json(
            &harness,
            &format!("{}/recover/idv/initiate", base(&harness)),
            &json!({ "identifier": prover, "code": code, "provider": provider }),
            None,
            None,
        )
        .await;
        assert_eq!(
            (status, parsed),
            refusal,
            "an unknown or absent provider ({provider}) must not be distinguishable"
        );
        assert!(!sets_session_cookie(&headers));
    }

    // (3) NO PENDING FLOW: a perfect proof for an account that never opened a case.
    let orphan = "orphan@example.test";
    let orphan_subject = harness
        .seed_user(orphan, "correct horse battery staple")
        .await;
    let code = recovery_code(&harness, &sender, orphan).await;
    let (status, headers, parsed) = post_json(
        &harness,
        &format!("{}/recover/finalize", base(&harness)),
        &json!({ "identifier": orphan, "code": code }),
        None,
        None,
    )
    .await;
    assert_eq!((status, parsed), refusal, "no pending flow");
    assert!(!sets_session_cookie(&headers));

    // (4) UNSATISFIED METHOD: a real pending admin-approved case that no admin approved.
    let code = recovery_code(&harness, &sender, orphan).await;
    let (status, _headers, body) = post_json(
        &harness,
        &format!("{}/recover/admin-approved/initiate", base(&harness)),
        &json!({ "identifier": orphan, "code": code }),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(only_flow(&harness, &orphan_subject).await.1, "initiated");
    let code = recovery_code(&harness, &sender, orphan).await;
    let (status, headers, parsed) = post_json(
        &harness,
        &format!("{}/recover/finalize", base(&harness)),
        &json!({ "identifier": orphan, "code": code }),
        None,
        None,
    )
    .await;
    assert_eq!((status, parsed), refusal, "unsatisfied method");
    assert!(!sets_session_cookie(&headers));
    assert_eq!(
        only_flow(&harness, &orphan_subject).await.1,
        "initiated",
        "and the case was not completed by the refusal"
    );

    // (5) THE ACCOUNT-LIFECYCLE FENCE: every gate above passes and `establish_session` is the
    // thing that refuses. Its `NotAuthenticatable` is a DIFFERENT error from a store fault, so
    // rendering it distinctly (a 423, say) would be an account-state oracle available to
    // anyone holding a live one-time code.
    let fenced = "fenced@example.test";
    let fenced_subject = harness
        .seed_user_in_state(
            fenced,
            "correct horse battery staple",
            ironauth_store::UserState::Disabled,
        )
        .await;
    let code = recovery_code(&harness, &sender, fenced).await;
    let (status, _headers, body) = post_json(
        &harness,
        &format!("{}/recover/admin-approved/initiate", base(&harness)),
        &json!({ "identifier": fenced, "code": code }),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    let (fenced_flow, _state, _acr) = only_flow(&harness, &fenced_subject).await;
    sqlx::query("UPDATE recovery_approvals SET state = 'approved' WHERE flow_id = $1")
        .bind(&fenced_flow)
        .execute(harness.db().owner_pool())
        .await
        .expect("the control plane approves");
    let code = recovery_code(&harness, &sender, fenced).await;
    let (status, headers, parsed) = post_json(
        &harness,
        &format!("{}/recover/finalize", base(&harness)),
        &json!({ "identifier": fenced, "code": code }),
        None,
        None,
    )
    .await;
    assert_eq!((status, parsed), refusal, "the account-lifecycle fence");
    assert!(
        !sets_session_cookie(&headers),
        "a fenced account mints no session however satisfied its recovery case is"
    );
}

/// With the experimental feature OFF, every hosted route answers the SAME uniform 404 the PR 3
/// routes do, and nothing is created.
#[tokio::test]
async fn the_hosted_routes_are_404_with_the_flag_off() {
    let harness = Harness::start_store_backed().await;
    let identifier = "offflag@example.test";
    let subject = harness
        .seed_user(identifier, "correct horse battery staple")
        .await;
    for endpoint in [
        "recover/admin-approved/initiate",
        "recover/idv/initiate",
        "recover/finalize",
    ] {
        let path = format!("{}/{endpoint}", base(&harness));
        let (status, _headers, _body) = post_json(
            &harness,
            &path,
            &json!({ "identifier": identifier, "code": "123456" }),
            None,
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{endpoint} is inert with the advanced-recovery feature off"
        );
    }
    let flows: i64 = sqlx::query_scalar("SELECT count(*) FROM recovery_flows WHERE subject = $1")
        .bind(&subject)
        .fetch_one(harness.db().owner_pool())
        .await
        .expect("count");
    assert_eq!(flows, 0, "an inert surface creates nothing");
}

// -------------------------------------------------------------------------------------------
// IDV: the hosted initiation, the real signed callback, and the hosted finalize.
// -------------------------------------------------------------------------------------------

/// The IDV mode end to end over HTTP: the hosted initiation returns the provider redirect
/// carrying the case binding, the provider's signed PASS callback satisfies the method, and
/// only after the delay window does the hosted finalize establish the session.
#[tokio::test]
async fn the_hosted_idv_mode_runs_end_to_end_through_the_delay_gate() {
    let key = idv_key(1, IDV_KID);
    let (harness, sender) = hosted_harness(&key).await;
    let identifier = "idv@example.test";
    let (subject, _typed) = seed_passkey_user(&harness, identifier).await;

    let code = recovery_code(&harness, &sender, identifier).await;
    let (status, _headers, body) = post_json(
        &harness,
        &format!("{}/recover/idv/initiate", base(&harness)),
        &json!({ "identifier": identifier, "code": code, "provider": IDV_SLUG }),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    let redirect = body["redirect_url"]
        .as_str()
        .expect("a redirect url")
        .to_owned();
    let (flow_id, state, acr) = only_flow(&harness, &subject).await;
    assert_eq!(state, "held");
    assert_eq!(acr, RecoveryFactor::EmailOtp.strength_acr());

    // The case binding the provider must echo rides the redirect URL.
    let query = redirect.split_once('?').expect("a query string").1;
    let mut idv_state = String::new();
    let mut nonce = String::new();
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=').expect("a name=value pair");
        match name {
            "state" => idv_state = value.to_owned(),
            "nonce" => nonce = value.to_owned(),
            _ => {}
        }
    }
    assert!(!idv_state.is_empty() && !nonce.is_empty());

    // The provider's signed PASS callback satisfies the method, but not the delay.
    let aud = harness.state().issuer_for(&harness.scope());
    let callback = signed_callback(
        &key,
        IDV_ISS,
        &aud,
        now_secs(&harness),
        &flow_id,
        &idv_state,
        &nonce,
        "pass",
    );
    assert_eq!(
        post_idv_callback(&harness, callback).await,
        StatusCode::ACCEPTED
    );
    assert_eq!(only_flow(&harness, &subject).await.1, "held");

    let code = recovery_code(&harness, &sender, identifier).await;
    let (status, headers, _body) = post_json(
        &harness,
        &format!("{}/recover/finalize", base(&harness)),
        &json!({ "identifier": identifier, "code": code }),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "the delay still holds");
    assert!(!sets_session_cookie(&headers));

    // After the delay window, the hosted finalize establishes the recovered session.
    harness.clock().advance(Duration::from_secs(5));
    let code = recovery_code(&harness, &sender, identifier).await;
    let (status, headers, body) = post_json(
        &harness,
        &format!("{}/recover/finalize", base(&harness)),
        &json!({ "identifier": identifier, "code": code }),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert!(sets_session_cookie(&headers));
    assert_eq!(only_flow(&harness, &subject).await.1, "completed");
    // The flow's stored recover_acr never moved off the pwd floor.
    assert_eq!(
        flow_recover_acr(&harness, &flow_id).await,
        RecoveryFactor::EmailOtp.strength_acr()
    );
}
