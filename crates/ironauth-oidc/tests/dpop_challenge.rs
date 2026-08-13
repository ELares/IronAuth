// SPDX-License-Identifier: MIT OR Apache-2.0

//! `DPoP` (RFC 9449) DEVICE BINDING of the Authorization Challenge Endpoint's `auth_session`
//! (issue #368, draft-ietf-oauth-first-party-apps-03: "the `auth_session` SHOULD be device-bound").
//!
//! The rule under test is an ASYMMETRY. On the FRESH request a proof is OPTIONAL: present one and
//! the `auth_session` is bound to its key, present none and the session is the pre-#368 unbound
//! bearer handle. On every RESUME hop the stashed binding decides: a BOUND session REQUIRES a
//! fresh, non-replayed proof for the SAME key, and an UNBOUND session ignores the header entirely
//! so no proof can bind it after the fact.
//!
//! Two properties get adversarial attention because they are what the binding is FOR:
//!
//! 1. A stolen `auth_session` presented WITHOUT the private key does not resume. That is the theft
//!    resistance; without it the feature is decoration.
//! 2. Every refusal on the resume path is byte-identical to the endpoint's ordinary stale-handle
//!    rejection. A distinguishable one would tell a thief their stolen handle is live.

mod common;

use std::time::{Duration, SystemTime};

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{Harness, form, json, send_through};
use ironauth_env::Clock;
use ironauth_jose::dpop_test_util::sign_proof;
use ironauth_jose::{SigningKey, SigningPolicy};
use ironauth_oidc::{DiscoveryCapabilities, discovery_document};

/// The identifier and password the suite's first-party user is seeded with.
const IDENTIFIER: &str = "native@example.test";
const PASSWORD: &str = "correct horse battery staple";
/// The TOTP seed `seed_active_totp` enrolls, so a real second-factor code is reproducible.
const TOTP_SEED: [u8; 20] = [0x0A; 20];

/// A fixed Ed25519 client proof key: the key a compliant native client would hold in its device
/// keystore and never export.
fn proof_key() -> SigningKey {
    SigningKey::ed25519_from_seed(Some("challenge-dpop".to_owned()), &[7_u8; 32]).expect("ed25519")
}

/// A DIFFERENT proof key, standing in for a thief who stole the `auth_session` but holds their own
/// keypair rather than the victim's.
fn other_key() -> SigningKey {
    SigningKey::ed25519_from_seed(Some("thief".to_owned()), &[9_u8; 32]).expect("ed25519")
}

/// Start a harness with the challenge feature armed, a first-party client, and a seeded user whose
/// ACTIVE TOTP factor plus the tenant MFA baseline force the login to HOLD on a second factor, so
/// every test here has a real resume hop to bind.
async fn armed_mfa_harness() -> (Harness, String) {
    let mut harness = Harness::start().await;
    harness.enable_first_party_challenge();
    let client_id = *harness.client_id();
    harness.set_client_first_party(&client_id, true).await;
    let subject = harness.seed_user(IDENTIFIER, PASSWORD).await;
    harness.seed_active_totp(&subject).await;
    harness.set_tenant_min_class("mfa").await;
    (harness, client_id.to_string())
}

/// The scope-routed challenge endpoint path the router mounts.
fn challenge_path(harness: &Harness) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/authorize-challenge",
        scope.tenant(),
        scope.environment()
    )
}

/// The `htu` a compliant client signs: the ABSOLUTE per-environment challenge endpoint URL.
///
/// Derived from [`common::ISSUER_BASE`] plus the mounted path, which is what a real client builds
/// from the `authorization_challenge_endpoint` discovery advertises. Unlike `/token` and
/// `/userinfo`, this endpoint lives UNDER the per-environment issuer, so a proof signed against
/// the deployment root would be refused;
/// `the_htu_matches_the_advertised_challenge_endpoint` pins that this string is the advertised one.
fn expected_htu(harness: &Harness) -> String {
    format!("{}{}", common::ISSUER_BASE, challenge_path(harness))
}

/// The whole-seconds `iat` a proof carries, read from the harness clock so it is fresh at
/// `state.now()`.
fn now_secs(harness: &Harness) -> u64 {
    harness
        .state()
        .now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// A well-formed, fresh `POST` proof for the challenge endpoint, signed by `key`.
fn fresh_proof(harness: &Harness, key: &SigningKey, jti: &str) -> String {
    sign_proof(key, "POST", &expected_htu(harness), now_secs(harness), jti)
}

/// A real TOTP code for the seeded factor at the current app-clock time.
fn totp_code(harness: &Harness) -> String {
    ironauth_jose::code_at(
        &TOTP_SEED,
        ironauth_jose::TotpParams::authenticator_default(),
        harness
            .clock()
            .now_utc()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("after epoch")
            .as_secs(),
    )
}

/// POST a form to the challenge endpoint with zero or more `DPoP` header values.
async fn challenge_with_dpop(
    harness: &Harness,
    body: &str,
    dpop_values: &[&str],
) -> (StatusCode, String) {
    challenge_from(harness, body, dpop_values, "198.51.100.7").await
}

/// [`challenge_with_dpop`] from a NAMED peer IP.
///
/// The endpoint's fresh-request rate cap (issue #93 PR4) is keyed on the client AND the resolved
/// peer IP, and it runs BEFORE proof validation, so a test that presents several bad proofs in a
/// row from one address is shed by the cap and never reaches the check it means to exercise.
/// Giving each case its own address keeps the cap's behavior intact while still testing the proof
/// rules; `x-ironauth-peer-ip` is the non-forgeable header (issue #31) the resolver reads.
async fn challenge_from(
    harness: &Harness,
    body: &str,
    dpop_values: &[&str],
    peer_ip: &str,
) -> (StatusCode, String) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(challenge_path(harness))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("x-ironauth-peer-ip", peer_ip);
    for value in dpop_values {
        builder = builder.header("DPoP", *value);
    }
    let request = builder
        .body(Body::from(body.to_owned()))
        .expect("request builds");
    let (status, _headers, response) = harness.send(request).await;
    (status, response)
}

/// The token endpoint's `htu`: the DEPLOYMENT-ROOT `/token`, NOT the per-environment path the
/// challenge endpoint uses. The two differ, and a proof minted for one is refused at the other,
/// which is exactly the property the challenge suite relies on when it shares a replay cache.
fn token_htu() -> String {
    format!("{}/token", common::ISSUER_BASE)
}

/// `POST /token` with zero or more `DPoP` header values.
async fn token_with_dpop(
    harness: &Harness,
    form_body: &str,
    dpop_values: &[&str],
) -> (StatusCode, String) {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    for value in dpop_values {
        builder = builder.header("DPoP", *value);
    }
    let request = builder
        .body(Body::from(form_body.to_owned()))
        .expect("request builds");
    let (status, _headers, body) = send_through(harness.router(), request).await;
    (status, body)
}

/// A fresh, well-formed proof for the TOKEN endpoint, signed by `key`.
fn token_proof(harness: &Harness, key: &SigningKey, jti: &str) -> String {
    sign_proof(key, "POST", &token_htu(), now_secs(harness), jti)
}

/// The redemption form for a browserless first-party code: no `redirect_uri`.
fn redeem_form(code: &str, client_id: &str) -> String {
    form(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("client_id", client_id),
    ])
}

/// Drive a complete bound login and return the minted code plus the key it is bound to.
async fn bound_code(harness: &Harness, client_id: &str, key: &SigningKey) -> String {
    let auth_session = first_hop(
        harness,
        client_id,
        &[&fresh_proof(harness, key, "jti-mint-first")],
    )
    .await;
    harness.clock().advance(Duration::from_secs(90));
    let (status, body) = challenge_with_dpop(
        harness,
        &form(&[
            ("auth_session", &auth_session),
            ("otp", &totp_code(harness)),
        ]),
        &[&fresh_proof(harness, key, "jti-mint-resume")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the bound login mints: {body}");
    json(&body)["authorization_code"]
        .as_str()
        .unwrap_or_else(|| panic!("a code: {body}"))
        .to_owned()
}

/// The fresh first hop (identifier + password), returning the `auth_session` the step-up render
/// carries. `dpop_values` are the proof headers presented on that FRESH request, which is what
/// decides whether the resulting session is bound.
async fn first_hop(harness: &Harness, client_id: &str, dpop_values: &[&str]) -> String {
    let body = form(&[
        ("client_id", client_id),
        ("response_type", "code"),
        ("username", IDENTIFIER),
        ("password", PASSWORD),
    ]);
    let (status, body) = challenge_with_dpop(harness, &body, dpop_values).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the primary factor holds on the second factor: {body}"
    );
    assert_eq!(json(&body)["error"], "insufficient_authorization");
    json(&body)["auth_session"]
        .as_str()
        .unwrap_or_else(|| panic!("an auth_session in the step-up render: {body}"))
        .to_owned()
}

/// The uniform stale-handle rejection the resume path returns for EVERY refusal, captured once so
/// each test compares against the same pair rather than restating it.
const UNIFORM_RESUME_REFUSAL: (StatusCode, &str) = (StatusCode::BAD_REQUEST, "invalid_grant");

/// Assert a resume response is the uniform stale-handle refusal, body and all.
fn assert_uniform_refusal(status: StatusCode, body: &str, what: &str) {
    let (expected_status, expected_error) = UNIFORM_RESUME_REFUSAL;
    assert_eq!(status, expected_status, "{what}: {body}");
    assert_eq!(json(body)["error"], expected_error, "{what}: {body}");
    assert!(
        json(body)["auth_session"].is_null(),
        "{what} must not hand back a fresh handle: {body}"
    );
}

// ---------------------------------------------------------------------------------------------
// The htu contract.
// ---------------------------------------------------------------------------------------------

/// The `htu` the server validates a proof against MUST equal the
/// `authorization_challenge_endpoint` that discovery advertises, because that URL is what a
/// compliant client reads and POSTs to.
///
/// This endpoint is the EXCEPTION to the token-endpoint rule: it is scope-routed UNDER the
/// per-environment issuer rather than mounted at the deployment root. A server that copied
/// `/token`'s deployment-root derivation would reject every compliant client, and no test that
/// signed its htu from the server's own helper would notice, because both sides would be wrong
/// together.
///
/// The pin closes that loop from the other end. `expected_htu` is the string every proof in this
/// file is signed with, and the positive-control tests prove the SERVER accepts exactly it; this
/// asserts DISCOVERY publishes exactly it too, so the client-visible contract and the server's
/// check are one string. Whether the key is advertised AT ALL is a feature-ladder question owned
/// by the `discovery` suite, so the capability is armed directly here.
#[tokio::test]
async fn the_htu_matches_the_advertised_challenge_endpoint() {
    let (harness, _client_id) = armed_mfa_harness().await;
    let scope = harness.scope();
    let issuer = format!(
        "{}/t/{}/e/{}",
        common::ISSUER_BASE,
        scope.tenant(),
        scope.environment()
    );
    let document = discovery_document(
        &issuer,
        common::ISSUER_BASE,
        &format!("{issuer}/jwks.json"),
        &SigningPolicy::eddsa_default(),
        &DiscoveryCapabilities::default().with_first_party_challenge_endpoint(true),
    );
    assert_eq!(
        document["authorization_challenge_endpoint"].as_str(),
        Some(expected_htu(&harness).as_str()),
        "discovery must advertise exactly the htu the server validates proofs against"
    );
}

// ---------------------------------------------------------------------------------------------
// The fresh request: binding is opportunistic.
// ---------------------------------------------------------------------------------------------

/// The pre-#368 posture is untouched: no proof, no binding, and the resume needs none. This is the
/// compatibility floor for every native client that has not adopted `DPoP`.
#[tokio::test]
async fn a_session_created_without_a_proof_resumes_without_one() {
    let (harness, client_id) = armed_mfa_harness().await;
    let auth_session = first_hop(&harness, &client_id, &[]).await;

    harness.clock().advance(Duration::from_secs(90));
    let (status, body) = challenge_with_dpop(
        &harness,
        &form(&[
            ("auth_session", &auth_session),
            ("otp", &totp_code(&harness)),
        ]),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the unbound resume mints: {body}");
    assert!(
        json(&body)["authorization_code"]
            .as_str()
            .is_some_and(|code| code.starts_with("ac_")),
        "a browserless code: {body}"
    );
}

/// A present-but-invalid proof on the FRESH request is refused outright and NEVER silently
/// downgraded to an unbound session.
///
/// The downgrade is the dangerous failure: a client that asked for sender constraining would
/// believe it had a bound session while holding a plain bearer handle, and nothing in its own
/// responses would say otherwise.
#[tokio::test]
async fn an_invalid_proof_on_a_fresh_request_is_refused_not_downgraded() {
    let (harness, client_id) = armed_mfa_harness().await;
    // The harness clock starts near the epoch, so move it well past the freshness window before
    // building a deliberately STALE proof; otherwise `now - 3600` underflows rather than being old.
    harness.clock().advance(Duration::from_secs(86_400));
    let key = proof_key();
    let body = form(&[
        ("client_id", &client_id),
        ("response_type", "code"),
        ("username", IDENTIFIER),
        ("password", PASSWORD),
    ]);

    // Every one of these is a distinct defect in an OTHERWISE well-formed proof, so each pins a
    // separate check rather than all of them failing at the same first hurdle.
    let wrong_htu = sign_proof(
        &key,
        "POST",
        &format!("{}/token", common::ISSUER_BASE),
        now_secs(&harness),
        "jti-htu",
    );
    let bound_to_get = sign_proof(
        &key,
        "GET",
        &expected_htu(&harness),
        now_secs(&harness),
        "jti-htm",
    );
    let stale_iat = sign_proof(
        &key,
        "POST",
        &expected_htu(&harness),
        now_secs(&harness) - 3_600,
        "jti-iat",
    );
    let mut tampered = fresh_proof(&harness, &key, "jti-sig");
    // Flip the last signature character, so the JWS parses and only the signature fails.
    let flipped = if tampered.ends_with('A') { 'B' } else { 'A' };
    tampered.pop();
    tampered.push(flipped);

    for (index, (label, proof)) in [
        ("a proof for the token endpoint's htu", wrong_htu.as_str()),
        ("a proof bound to GET", bound_to_get.as_str()),
        ("a proof whose iat is an hour old", stale_iat.as_str()),
        ("a proof whose signature was tampered", tampered.as_str()),
        ("a proof that is not even a JWS", "not-a-proof"),
    ]
    .into_iter()
    .enumerate()
    {
        let peer = format!("198.51.100.{}", index + 20);
        let (status, response) = challenge_from(&harness, &body, &[proof], &peer).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{label} must be refused: {response}"
        );
        assert_eq!(
            json(&response)["error"],
            "invalid_dpop_proof",
            "{label} must be a proof refusal and not a silent unbound session: {response}"
        );
        assert!(
            json(&response)["auth_session"].is_null(),
            "{label} must not hand back a usable session: {response}"
        );
    }

    // Two headers: RFC 9449 permits exactly one, and taking the first would let an attacker append
    // a header the server and an intermediary disagree about.
    let one = fresh_proof(&harness, &key, "jti-a");
    let two = fresh_proof(&harness, &key, "jti-b");
    let (status, response) = challenge_from(&harness, &body, &[&one, &two], "198.51.100.60").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "two headers: {response}");
    assert_eq!(json(&response)["error"], "invalid_dpop_proof");
}

// ---------------------------------------------------------------------------------------------
// The resume hop: binding is mandatory once set.
// ---------------------------------------------------------------------------------------------

/// The whole point, end to end: a session bound on the fresh request resumes and mints when the
/// SAME key re-proves possession.
///
/// This is the positive control for every refusal below. Without it, a server that refused all
/// resumes would pass the negative tests.
#[tokio::test]
async fn a_bound_session_resumes_and_mints_with_the_same_key() {
    let (harness, client_id) = armed_mfa_harness().await;
    let key = proof_key();
    let first = fresh_proof(&harness, &key, "jti-first");
    let auth_session = first_hop(&harness, &client_id, &[&first]).await;

    harness.clock().advance(Duration::from_secs(90));
    let resume_proof = fresh_proof(&harness, &key, "jti-resume");
    let (status, body) = challenge_with_dpop(
        &harness,
        &form(&[
            ("auth_session", &auth_session),
            ("otp", &totp_code(&harness)),
        ]),
        &[&resume_proof],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the bound resume mints: {body}");
    let code = json(&body)["authorization_code"]
        .as_str()
        .unwrap_or_else(|| panic!("a code: {body}"))
        .to_owned();

    // The code redeems at the ordinary token endpoint under the SAME key. This assertion changed
    // with the code-binding work: before it, this redemption carried no proof at all, because an
    // unbound code was all the mint produced.
    let (status, response) = token_with_dpop(
        &harness,
        &redeem_form(&code, &client_id),
        &[&token_proof(&harness, &key, "jti-redeem")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the code redeems: {response}");
    assert!(json(&response)["access_token"].is_string());
}

// ---------------------------------------------------------------------------------------------
// The minted code carries the binding (the second draft SHOULD).
// ---------------------------------------------------------------------------------------------

/// A code minted from a device-bound login is SENDER-CONSTRAINED: redeeming it without a proof is
/// refused, and refused WITHOUT burning the code.
///
/// The no-proof case is the one that matters. Without it, a code intercepted between the challenge
/// response and the token request could be cashed in by anyone, for plain bearer tokens, and the
/// device binding that protected every step of the login would have protected nothing at the one
/// moment it was worth stealing.
///
/// The successful redemption AFTER the refusal is not decoration: it proves the refusal rejected
/// the presentation rather than consuming the one-time code, so a legitimate client that simply
/// forgot its proof header can retry.
#[tokio::test]
async fn a_bound_code_is_refused_without_a_proof_and_survives_the_refusal() {
    let (harness, client_id) = armed_mfa_harness().await;
    let key = proof_key();
    let code = bound_code(&harness, &client_id, &key).await;

    let (status, body) = token_with_dpop(&harness, &redeem_form(&code, &client_id), &[]).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a bound code must not redeem bare: {body}"
    );
    assert_eq!(json(&body)["error"], "invalid_dpop_proof", "{body}");
    assert!(
        json(&body)["access_token"].is_null(),
        "no token may be issued: {body}"
    );

    // The code is still live for the legitimate holder.
    let (status, body) = token_with_dpop(
        &harness,
        &redeem_form(&code, &client_id),
        &[&token_proof(&harness, &key, "jti-retry")],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the refusal must not have burned the code: {body}"
    );
    assert!(json(&body)["access_token"].is_string());
}

/// A bound code is refused under a DIFFERENT key, even though that proof is itself perfectly
/// valid. A server that merely checked "is there a valid proof" would pass every other test here
/// and fail this one.
#[tokio::test]
async fn a_bound_code_is_refused_under_a_different_key() {
    let (harness, client_id) = armed_mfa_harness().await;
    let key = proof_key();
    let code = bound_code(&harness, &client_id, &key).await;

    let thief = token_proof(&harness, &other_key(), "jti-thief-redeem");
    let (status, body) =
        token_with_dpop(&harness, &redeem_form(&code, &client_id), &[&thief]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(json(&body)["error"], "invalid_dpop_proof", "{body}");

    let (status, body) = token_with_dpop(
        &harness,
        &redeem_form(&code, &client_id),
        &[&token_proof(&harness, &key, "jti-owner-redeem")],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the bound key still redeems, so the refusal was the key and not the code: {body}"
    );
}

/// The compatibility floor: a code from an UNBOUND browserless login still redeems with no proof.
///
/// This is what keeps the binding opt-in end to end. Every native client that has not adopted `DPoP`
/// must be unaffected by all of issue #368, and a code-side check written as "require a proof
/// whenever the code came from the challenge endpoint" would break every one of them.
#[tokio::test]
async fn an_unbound_browserless_code_still_redeems_without_a_proof() {
    let (harness, client_id) = armed_mfa_harness().await;
    let auth_session = first_hop(&harness, &client_id, &[]).await;
    harness.clock().advance(Duration::from_secs(90));
    let (status, body) = challenge_with_dpop(
        &harness,
        &form(&[
            ("auth_session", &auth_session),
            ("otp", &totp_code(&harness)),
        ]),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the unbound login mints: {body}");
    let code = json(&body)["authorization_code"]
        .as_str()
        .unwrap_or_else(|| panic!("a code: {body}"))
        .to_owned();

    let (status, body) = token_with_dpop(&harness, &redeem_form(&code, &client_id), &[]).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an unbound code must redeem bare, exactly as before issue #368: {body}"
    );
    assert!(json(&body)["access_token"].is_string());
}

/// THE theft-resistance property: a stolen `auth_session` presented with NO proof does not resume
/// a bound session.
///
/// The control is what makes this meaningful. The very same handle, same OTP, same clock, resumes
/// successfully in `a_bound_session_resumes_and_mints_with_the_same_key`; the only difference here
/// is the missing key, so the refusal can only be the binding.
#[tokio::test]
async fn a_stolen_bound_session_does_not_resume_without_the_key() {
    let (harness, client_id) = armed_mfa_harness().await;
    let key = proof_key();
    let first = fresh_proof(&harness, &key, "jti-first");
    let auth_session = first_hop(&harness, &client_id, &[&first]).await;

    harness.clock().advance(Duration::from_secs(90));
    let body = form(&[
        ("auth_session", &auth_session),
        ("otp", &totp_code(&harness)),
    ]);

    // No proof at all: the thief has the handle and the OTP but not the private key.
    let (status, response) = challenge_with_dpop(&harness, &body, &[]).await;
    assert_uniform_refusal(status, &response, "a bound resume with no proof");

    // A proof from the thief's OWN key: well-formed, fresh, and verifiable, but not the bound key.
    // This is the check that a server merely validating "some valid proof" would fail.
    let thief = fresh_proof(&harness, &other_key(), "jti-thief");
    let (status, response) = challenge_with_dpop(&harness, &body, &[&thief]).await;
    assert_uniform_refusal(status, &response, "a bound resume under a different key");

    // The bound key still works AFTER those refusals, proving they rejected the presentation
    // rather than burning the session (a legitimate client must survive a thief's attempts).
    let good = fresh_proof(&harness, &key, "jti-good");
    let (status, response) = challenge_with_dpop(&harness, &body, &[&good]).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the legitimate holder still resumes after the failed attempts: {response}"
    );
}

/// A replayed proof does not resume: the `jti` is single-use inside the freshness window, so a
/// proof captured off the wire cannot be re-presented.
///
/// The follow-up with a FRESH `jti` from the same key is what proves the refusal was the replay
/// and not the session having been consumed by the first attempt.
#[tokio::test]
async fn a_replayed_proof_does_not_resume_a_bound_session() {
    let (harness, client_id) = armed_mfa_harness().await;
    let key = proof_key();
    let auth_session = first_hop(
        &harness,
        &client_id,
        &[&fresh_proof(&harness, &key, "jti-first")],
    )
    .await;

    // 35 seconds: past the 30-second TOTP step, so the code below is a fresh one, but well inside
    // the 60-second DPoP freshness window, so the proof minted here is STILL FRESH when it is
    // re-presented. That distinction is the whole test. Re-presenting a proof from BEFORE the
    // window is refused for being STALE, which is a different rule, and a server with no replay
    // cache at all would pass a test written that way.
    harness.clock().advance(Duration::from_secs(35));
    let replayed = fresh_proof(&harness, &key, "jti-replayed");
    let otp = totp_code(&harness);

    // First presentation: a WRONG otp, so the hop is refused for a reason that leaves the flow
    // alive and hands back a rotated handle. The proof itself was accepted and its jti recorded.
    let (status, body) = challenge_with_dpop(
        &harness,
        &form(&[("auth_session", &auth_session), ("otp", "000000")]),
        &[&replayed],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a wrong otp loops: {body}");
    let next = json(&body)["auth_session"]
        .as_str()
        .unwrap_or_else(|| panic!("the loop hands back a rotated handle: {body}"))
        .to_owned();

    // The SAME proof again, same key, same jti, still inside the freshness window: a replay.
    let (status, body) = challenge_with_dpop(
        &harness,
        &form(&[("auth_session", &next), ("otp", &otp)]),
        &[&replayed],
    )
    .await;
    assert_uniform_refusal(
        status,
        &body,
        "a replayed proof jti inside the freshness window",
    );

    // The identical hop with a FRESH jti succeeds. That is what proves the refusal above was the
    // replay and not the handle, the otp, or the clock.
    let (status, body) = challenge_with_dpop(
        &harness,
        &form(&[("auth_session", &next), ("otp", &otp)]),
        &[&fresh_proof(&harness, &key, "jti-second")],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a fresh jti from the same key resumes: {body}"
    );
}

/// An UNBOUND session ignores the `DPoP` header entirely, so a proof can never bind it after the
/// fact.
///
/// Without this rule, a thief who stole an unbound handle could present their OWN key, bind the
/// session to it, and lock the legitimate client out of its own login. The two presentations here
/// (a valid proof from a fresh key, and a syntactically broken header) must BOTH pass through
/// untouched, which is what "not consulted" means as distinct from "accepted".
#[tokio::test]
async fn a_proof_cannot_bind_a_session_that_was_created_unbound() {
    let (harness, client_id) = armed_mfa_harness().await;
    let auth_session = first_hop(&harness, &client_id, &[]).await;

    harness.clock().advance(Duration::from_secs(90));
    // A wrong OTP so the flow LOOPS rather than completing, leaving a session to test twice.
    let looped = challenge_with_dpop(
        &harness,
        &form(&[("auth_session", &auth_session), ("otp", "000000")]),
        &[&fresh_proof(&harness, &other_key(), "jti-bind-attempt")],
    )
    .await;
    assert_eq!(
        looped.0,
        StatusCode::BAD_REQUEST,
        "a wrong otp loops: {}",
        looped.1
    );
    let next = json(&looped.1)["auth_session"]
        .as_str()
        .unwrap_or_else(|| panic!("the loop hands back a new handle: {}", looped.1))
        .to_owned();

    // A garbage header on an unbound session is likewise not consulted: if it were read at all,
    // this hop would be refused.
    let (status, body) = challenge_with_dpop(
        &harness,
        &form(&[("auth_session", &next), ("otp", &totp_code(&harness))]),
        &["not-a-proof-at-all"],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an unbound session completes regardless of the header: {body}"
    );
    assert!(
        json(&body)["authorization_code"].is_string(),
        "a code: {body}"
    );
}

/// Every resume refusal is BYTE-IDENTICAL to the endpoint's ordinary stale-handle rejection.
///
/// This is the anti-oracle invariant. If a missing or mismatched proof answered differently from a
/// forged handle, a thief could use the endpoint to sort live stolen handles from dead ones, and
/// for a PUBLIC client (which presents no client credential) that response is the only signal
/// there is. The comparison is against a handle that is genuinely garbage, so the two answers are
/// checked against each other rather than against a hardcoded expectation.
#[tokio::test]
async fn a_binding_refusal_is_indistinguishable_from_a_stale_handle() {
    let (harness, client_id) = armed_mfa_harness().await;
    let key = proof_key();
    let first = fresh_proof(&harness, &key, "jti-first");
    let auth_session = first_hop(&harness, &client_id, &[&first]).await;
    harness.clock().advance(Duration::from_secs(90));
    let otp = totp_code(&harness);

    // The baseline: a handle that never existed.
    let (stale_status, stale_body) = challenge_with_dpop(
        &harness,
        &form(&[("auth_session", "AAAAAAAAAAAAAAAA"), ("otp", &otp)]),
        &[],
    )
    .await;

    for (label, proofs) in [
        ("no proof on a bound session", Vec::new()),
        (
            "a proof under the wrong key",
            vec![fresh_proof(&harness, &other_key(), "jti-wrong")],
        ),
        ("a malformed proof header", vec!["not-a-proof".to_owned()]),
    ] {
        let borrowed: Vec<&str> = proofs.iter().map(String::as_str).collect();
        let (status, body) = challenge_with_dpop(
            &harness,
            &form(&[("auth_session", &auth_session), ("otp", &otp)]),
            &borrowed,
        )
        .await;
        assert_eq!(status, stale_status, "{label} must match the stale status");
        assert_eq!(
            body, stale_body,
            "{label} must be byte-identical to the stale-handle body, or it is an oracle"
        );
    }
}
