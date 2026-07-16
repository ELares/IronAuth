// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 9470 step-up authentication end to end (issue #72), against a real Postgres.
//!
//! These pin the acceptance-critical behavior that the surveyed field does not
//! ship:
//!
//! - a step-up authorization whose session does not meet the required `acr` RUNS a
//!   real second factor (the TOTP challenge) and issues tokens with a FRESH `acr` +
//!   `auth_time` reflecting what actually happened, never a silent reuse;
//! - a user without any qualifying factor is routed to the enrollment prompt;
//! - the per-scope policy is enforced at authorization, at token issuance, AND on
//!   refresh (a lapsed auth-age window on refresh triggers the step-up rather than
//!   silently succeeding with a stale `acr`/`auth_time`);
//! - a session already at the multi-factor level satisfies the floor and proceeds.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{
    Harness, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, enc, form, json, location,
    location_param, set_cookie_pair,
};
use ironauth_env::Clock;
use ironauth_jose::{TotpParams, base32_decode, code_at, verify};
use serde_json::{Value, json};
use std::time::{Duration, UNIX_EPOCH};

/// The IronAuth multi-factor ACR (issue #14): the floor a TOTP second factor meets.
const ACR_MFA: &str = "urn:ironauth:acr:mfa";

/// The credential-ladder ACR order (weakest first), the same one the AS uses by
/// default. A sample resource server compares an access token's `acr` against a
/// required floor by rank in this order.
const ACR_ORDER: &[&str] = &[
    "urn:ironauth:acr:pwd",
    "urn:ironauth:acr:mfa",
    "phr",
    "phrh",
];

/// The MINIMAL sample resource server (RFC 9470, issue #72): the challenge contract
/// the docs page documents, in code. It inspects an access token's claims and, when
/// the authentication context does not meet what the protected operation requires,
/// returns the 401 `WWW-Authenticate` challenge a client uses to step up; otherwise
/// it accepts. Kept tiny and dependency-free (it reuses the AS's own JOSE stack for
/// the token, and only the `acr` comparison lives here) so it is the documented,
/// exercised harness the acceptance criteria call for.
mod sample_rs {
    use super::{ACR_ORDER, URL_SAFE_NO_PAD};
    use base64::Engine;
    use serde_json::Value;

    /// The 401 challenge a resource server returns when the presented token's
    /// authentication context is insufficient.
    pub struct Challenge {
        /// The `acr` floor the client must reach on re-authorization.
        pub acr_values: String,
    }

    impl Challenge {
        /// The exact `WWW-Authenticate` header value (RFC 9470 section 3).
        pub fn www_authenticate(&self) -> String {
            format!(
                "Bearer error=\"insufficient_user_authentication\", \
                 error_description=\"a higher authentication context is required\", \
                 acr_values=\"{}\"",
                self.acr_values
            )
        }
    }

    /// The `acr` claim of a JWT access token (its middle segment), or `None`. A real
    /// RS verifies the token's signature first; this sample reads the claim after the
    /// AS-side test has already exercised the hardened verify path on the ID token.
    pub fn access_token_acr(token: &str) -> Option<String> {
        let payload = token.split('.').nth(1)?;
        let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
        let claims: Value = serde_json::from_slice(&bytes).ok()?;
        claims.get("acr")?.as_str().map(str::to_owned)
    }

    /// Whether `achieved` satisfies `required` under the ladder order (weakest first).
    fn satisfies(achieved: &str, required: &str) -> bool {
        if achieved == required {
            return true;
        }
        let rank = |acr: &str| ACR_ORDER.iter().position(|candidate| *candidate == acr);
        match (rank(achieved), rank(required)) {
            (Some(a), Some(r)) => a >= r,
            _ => false,
        }
    }

    /// The resource-server decision for a protected operation that requires
    /// `required_acr`: accept ([`Ok`]) when the token's `acr` satisfies it, otherwise
    /// return the [`Challenge`] the client steps up with.
    pub fn evaluate(token: &str, required_acr: &str) -> Result<(), Challenge> {
        let acr = access_token_acr(token);
        if acr
            .as_deref()
            .is_some_and(|acr| satisfies(acr, required_acr))
        {
            Ok(())
        } else {
            Err(Challenge {
                acr_values: required_acr.to_owned(),
            })
        }
    }
}

/// The current whole-second Unix time on the harness's deterministic clock.
fn now_secs(harness: &Harness) -> u64 {
    harness
        .clock()
        .now_utc()
        .duration_since(UNIX_EPOCH)
        .expect("after epoch")
        .as_secs()
}

/// The current instant in epoch microseconds (for seeding a session's `auth_time`).
fn now_micros(harness: &Harness) -> i64 {
    i64::try_from(now_secs(harness)).expect("in range") * 1_000_000
}

/// The current instant in epoch seconds as an `i64` (for comparing an `auth_time`
/// claim).
fn now_secs_i64(harness: &Harness) -> i64 {
    i64::try_from(now_secs(harness)).expect("in range")
}

/// Build a PKCE authorization query for `client_id` with an explicit `scope` and any
/// extra pre-encoded `key=value` fragments.
fn authorize_query(client_id: &str, scope: &str, extra: &[&str]) -> String {
    let mut query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&scope={}&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
        enc(scope),
    );
    for fragment in extra {
        query.push('&');
        query.push_str(fragment);
    }
    query
}

/// The standard PKCE token-exchange form for a public client's code.
fn token_form(code: &str, client_id: &str) -> String {
    form(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", client_id),
        ("code_verifier", PKCE_VERIFIER),
    ])
}

async fn post_json(
    harness: &Harness,
    path: &str,
    cookie: &str,
    body: &Value,
) -> (StatusCode, Value) {
    let (status, _headers, response) = harness
        .send(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, cookie)
                .body(Body::from(body.to_string()))
                .expect("request builds"),
        )
        .await;
    let value = if response.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&response).unwrap_or(Value::Null)
    };
    (status, value)
}

/// Drive a TOTP enrollment to ACTIVE for `subject` and return the opened seed, so a
/// test can compute a valid current code at the challenge.
async fn enroll_active_totp(harness: &Harness, subject: &str) -> Vec<u8> {
    let scope = harness.scope();
    let base = format!(
        "/t/{}/e/{}/account/mfa",
        scope.tenant(),
        scope.environment()
    );
    let (_id, cookie) = harness.session_with_id(subject, "pwd", 0).await;
    let (status, begun) =
        post_json(harness, &format!("{base}/totp/enroll"), &cookie, &json!({})).await;
    assert_eq!(status, StatusCode::CREATED, "enroll begin: {begun:?}");
    let credential_id = begun["credential_id"]
        .as_str()
        .expect("credential_id")
        .to_owned();
    let seed = base32_decode(begun["secret"].as_str().expect("secret")).expect("decode secret");
    let code = code_at(
        &seed,
        TotpParams::authenticator_default(),
        now_secs(harness),
    );
    let (status, activated) = post_json(
        harness,
        &format!("{base}/totp/verify-enrollment"),
        &cookie,
        &json!({ "credential_id": credential_id, "code": code }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "activate: {activated:?}");
    seed
}

/// The flagship acceptance test: a step-up authorization whose session does not meet
/// the required `acr` RUNS the TOTP second factor and issues tokens with a fresh
/// `acr` and `auth_time`.
#[tokio::test]
async fn a_per_scope_acr_floor_runs_the_second_factor_and_issues_fresh_acr_and_auth_time() {
    let harness = Harness::start().await;
    let client_id = *harness.client_id();
    let client = client_id.to_string();
    // Skip the consent gate so the flow focuses on the step-up.
    harness
        .configure_client_policy(&client_id, "explicit", true, false, None)
        .await;
    // scope payments:write requires acr mfa.
    harness
        .set_scope_step_up_policy("payments:write", Some(ACR_MFA), None)
        .await;

    let subject = harness.seed_unique_user().await;
    let seed = enroll_active_totp(&harness, &subject).await;

    // A session authenticated by password ONLY at the current instant (fresh enough
    // for a max_age=3600 request, but below the mfa acr floor).
    let original_auth_secs = now_secs_i64(&harness);
    let cookie = harness
        .session_cookie_at(&subject, "pwd", original_auth_secs * 1_000_000)
        .await;

    // Authorize: the pwd session does NOT meet the mfa floor, so it is redirected to
    // the step-up challenge (NOT silently issued a code). max_age=3600 makes the ID
    // token carry auth_time so the freshness can be asserted.
    let query = authorize_query(&client, "openid payments:write", &["max_age=3600"]);
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "authorize should redirect: {body}"
    );
    let loc = location(&headers).expect("a Location");
    assert!(
        loc.starts_with("/login/mfa"),
        "an unmet acr floor routes to the second-factor challenge, got {loc}"
    );
    let return_to = location_param(&headers, "return_to").expect("return_to in the challenge URL");

    // Advance the clock two full TOTP periods so the step-up instant is DISTINCT from
    // the original session auth_time AND lands in a fresh time-step (a code in the
    // enrollment step would be refused single-use). The fresh auth_time in the issued
    // token must reflect this instant.
    harness.clock().advance(Duration::from_secs(60));
    let stepped_up_secs = now_secs_i64(&harness);
    assert_ne!(stepped_up_secs, original_auth_secs);

    // Prove the second factor: POST a valid current TOTP code to the challenge.
    let code = code_at(
        &seed,
        TotpParams::authenticator_default(),
        now_secs(&harness),
    );
    let challenge_form = form(&[("code", &code), ("return_to", &return_to)]);
    let (status, headers, _) = harness
        .post_form("/login/mfa", &challenge_form, Some(&cookie))
        .await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "the challenge upgrades the session"
    );
    let upgraded_cookie = set_cookie_pair(&headers).expect("an upgraded session cookie");
    assert_eq!(
        location(&headers).as_deref(),
        Some(return_to.as_str()),
        "the challenge resumes the original authorization request"
    );

    // Resume the authorization with the upgraded session: now the acr floor is met,
    // so a code is issued.
    let (status, headers, body) = harness
        .get_with_cookie(&return_to, Some(&upgraded_cookie))
        .await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "the resumed request issues a code: {body}"
    );
    let code = location_param(&headers, "code").expect("a code after the step-up");

    // The tokens carry a FRESH acr + auth_time reflecting the step-up that actually
    // happened, never the stale password-only session.
    let (status, _, body) = harness.token(&token_form(&code, &client)).await;
    assert_eq!(status, StatusCode::OK, "token exchange: {body}");
    let id_token = json(&body)["id_token"]
        .as_str()
        .expect("id_token")
        .to_owned();
    let policy = harness.policy(&client);
    let verified = verify(&id_token, &policy, &common::verify_clock()).expect("id token verifies");
    let claims = Value::Object(verified.claims().raw().clone());

    assert_eq!(
        claims["acr"],
        json!(ACR_MFA),
        "the stepped-up token carries the honest multi-factor acr"
    );
    let amr: Vec<&str> = claims["amr"]
        .as_array()
        .expect("amr")
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(
        amr.contains(&"otp") && amr.contains(&"mfa") && amr.contains(&"pwd"),
        "amr {amr:?}"
    );
    // auth_time is FRESH (the step-up instant), never the stale session auth_time.
    assert_eq!(
        claims["auth_time"].as_i64(),
        Some(stepped_up_secs),
        "auth_time reflects the step-up, not the stale session"
    );
    assert_ne!(claims["auth_time"].as_i64(), Some(original_auth_secs));
}

/// A user without any qualifying factor is routed to the enrollment prompt (tenant
/// policy allows TOTP enrollment), never issued an under-qualified token.
#[tokio::test]
async fn a_missing_factor_routes_to_the_enrollment_prompt() {
    let harness = Harness::start().await;
    let client_id = *harness.client_id();
    let client = client_id.to_string();
    harness
        .configure_client_policy(&client_id, "explicit", true, false, None)
        .await;
    harness
        .set_scope_step_up_policy("payments:write", Some(ACR_MFA), None)
        .await;

    // A subject with NO second factor enrolled.
    let subject = harness.seed_unique_user().await;
    let cookie = harness
        .session_cookie_at(&subject, "pwd", now_micros(&harness))
        .await;

    let query = authorize_query(&client, "openid payments:write", &[]);
    let (status, headers, _) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let loc = location(&headers).expect("a Location");
    assert!(
        loc.starts_with("/login/mfa"),
        "routes to the challenge page, got {loc}"
    );
    assert!(
        loc.contains("enroll=1"),
        "a user without a qualifying factor gets the enrollment prompt, got {loc}"
    );

    // The challenge page renders the enrollment prompt (a link to the enroll surface).
    let (status, _, body) = harness.get_with_cookie(&loc, Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Set up a second factor"),
        "the enrollment prompt is shown"
    );
}

/// The per-scope policy is enforced at TOKEN ISSUANCE: a code issued before a policy
/// tightened is refused at the token endpoint with the RFC 9470 step-up error rather
/// than minting an under-qualified token.
#[tokio::test]
async fn a_per_scope_policy_is_enforced_at_token_issuance() {
    let harness = Harness::start().await;
    let client_id = *harness.client_id();
    let client = client_id.to_string();
    harness
        .configure_client_policy(&client_id, "explicit", true, false, None)
        .await;

    let subject = harness.seed_unique_user().await;
    let cookie = harness
        .session_cookie_at(&subject, "pwd", now_micros(&harness))
        .await;

    // No policy yet: a password session is issued a code for payments:write.
    let query = authorize_query(&client, "openid payments:write", &[]);
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "authorize: {body}");
    let code = location_param(&headers, "code").expect("a code");

    // The policy tightens AFTER the code was issued: the token endpoint re-evaluates
    // it against the frozen (password-only) authentication and refuses.
    harness
        .set_scope_step_up_policy("payments:write", Some(ACR_MFA), None)
        .await;

    let (status, _, body) = harness.token(&token_form(&code, &client)).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "issuance is refused: {body}"
    );
    let value = json(&body);
    assert_eq!(value["error"], json!("insufficient_user_authentication"));
    assert_eq!(value["acr_values"], json!(ACR_MFA));
}

/// A refresh whose auth-age window has LAPSED triggers the step-up requirement
/// rather than silently succeeding with a stale `acr`/`auth_time`.
#[tokio::test]
async fn a_refresh_reevaluates_a_lapsed_auth_age_window() {
    let harness = Harness::start().await;
    let client_id = *harness.client_id();
    let client = client_id.to_string();
    harness
        .configure_client_policy(&client_id, "explicit", true, false, None)
        .await;
    // scope reports:read must be authenticated within 300 seconds.
    harness
        .set_scope_step_up_policy("reports:read", None, Some(300))
        .await;

    let subject = harness.seed_unique_user().await;
    let cookie = harness
        .session_cookie_at(&subject, "pwd", now_micros(&harness))
        .await;

    // Authorize + token: the session is fresh, so a code and a refresh token issue,
    // and the family freezes auth_time (a max-age policy applies).
    let query = authorize_query(&client, "openid offline_access reports:read", &[]);
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "authorize: {body}");
    let code = location_param(&headers, "code").expect("a code");
    let (status, _, body) = harness.token(&token_form(&code, &client)).await;
    assert_eq!(status, StatusCode::OK, "token: {body}");
    let refresh_token = json(&body)["refresh_token"]
        .as_str()
        .expect("a refresh token")
        .to_owned();

    // A refresh WITHIN the window still succeeds.
    let refresh_form = form(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", &refresh_token),
        ("client_id", &client),
    ]);
    let (status, _, body) = harness.token(&refresh_form).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an in-window refresh succeeds: {body}"
    );
    let refresh_token = json(&body)["refresh_token"]
        .as_str()
        .expect("a rotated refresh token")
        .to_owned();

    // Advance the clock past the 300s window: the refresh must now trigger step-up.
    harness.clock().advance(Duration::from_secs(600));
    let refresh_form = form(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", &refresh_token),
        ("client_id", &client),
    ]);
    let (status, _, body) = harness.token(&refresh_form).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a lapsed auth-age window must not silently refresh: {body}"
    );
    let value = json(&body);
    assert_eq!(value["error"], json!("insufficient_user_authentication"));
    assert_eq!(value["max_age"], json!(300));
}

/// A session already at the multi-factor level satisfies an mfa floor and proceeds
/// straight to a code (the acr comparison honors the ordering: mfa meets mfa).
#[tokio::test]
async fn a_session_already_at_the_floor_proceeds_without_a_challenge() {
    let harness = Harness::start().await;
    let client_id = *harness.client_id();
    let client = client_id.to_string();
    harness
        .configure_client_policy(&client_id, "explicit", true, false, None)
        .await;
    harness
        .set_scope_step_up_policy("payments:write", Some(ACR_MFA), None)
        .await;

    let subject = harness.seed_unique_user().await;
    // A session recorded as password + TOTP already achieves the mfa acr.
    let cookie = harness
        .session_cookie_at(&subject, "pwd totp", now_micros(&harness))
        .await;

    let query = authorize_query(&client, "openid payments:write", &[]);
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "authorize: {body}");
    assert!(
        location_param(&headers, "code").is_some(),
        "a session already at the mfa floor is issued a code directly, not challenged"
    );
}

/// The sample resource server drives the FULL RFC 9470 round trip: it 401-challenges
/// a password-only access token with `insufficient_user_authentication` and
/// `acr_values`, the client re-authorizes (this time reaching the acr through a real
/// TOTP step-up), and the RS ACCEPTS the stepped-up token whose fresh `acr` reflects
/// what actually happened.
#[tokio::test]
async fn the_sample_resource_server_challenges_then_accepts_a_stepped_up_token() {
    let harness = Harness::start().await;
    let client_id = *harness.client_id();
    let client = client_id.to_string();
    harness
        .configure_client_policy(&client_id, "explicit", true, false, None)
        .await;

    let subject = harness.seed_unique_user().await;
    let seed = enroll_active_totp(&harness, &subject).await;
    let cookie = harness
        .session_cookie_at(&subject, "pwd", now_micros(&harness))
        .await;

    // 1. The client obtains a password-only access token (no acr requirement yet).
    let query = authorize_query(&client, "openid reports:read", &[]);
    let (status, headers, _) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let code = location_param(&headers, "code").expect("a code");
    let (status, _, body) = harness.token(&token_form(&code, &client)).await;
    assert_eq!(status, StatusCode::OK, "token: {body}");
    let pwd_access = json(&body)["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();

    // 2. The RS challenges it: a payments operation requires acr mfa.
    let challenge = sample_rs::evaluate(&pwd_access, ACR_MFA)
        .expect_err("a password-only token must be challenged");
    let header_value = challenge.www_authenticate();
    assert!(header_value.contains("error=\"insufficient_user_authentication\""));
    assert!(header_value.contains(&format!("acr_values=\"{ACR_MFA}\"")));

    // 3. The client re-authorizes carrying the challenged acr_values (RFC 9470): the
    //    AS runs the real second factor rather than reusing the session.
    let query = authorize_query(
        &client,
        "openid reports:read",
        &[&format!("acr_values={}", enc(&challenge.acr_values))],
    );
    let (status, headers, _) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let loc = location(&headers).expect("a Location");
    assert!(
        loc.starts_with("/login/mfa"),
        "acr_values drives the step-up, got {loc}"
    );
    let return_to = location_param(&headers, "return_to").expect("return_to");

    harness.clock().advance(Duration::from_secs(60));
    let code = code_at(
        &seed,
        TotpParams::authenticator_default(),
        now_secs(&harness),
    );
    let challenge_form = form(&[("code", &code), ("return_to", &return_to)]);
    let (status, headers, _) = harness
        .post_form("/login/mfa", &challenge_form, Some(&cookie))
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "the step-up succeeds");
    let upgraded = set_cookie_pair(&headers).expect("upgraded cookie");
    let (status, headers, _) = harness.get_with_cookie(&return_to, Some(&upgraded)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let code = location_param(&headers, "code").expect("a code after step-up");
    let (status, _, body) = harness.token(&token_form(&code, &client)).await;
    assert_eq!(status, StatusCode::OK, "token: {body}");
    let mfa_access = json(&body)["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();

    // 4. The RS ACCEPTS the stepped-up token: its fresh acr meets the requirement.
    assert_eq!(
        sample_rs::access_token_acr(&mfa_access).as_deref(),
        Some(ACR_MFA)
    );
    assert!(
        sample_rs::evaluate(&mfa_access, ACR_MFA).is_ok(),
        "the resource server accepts the stepped-up token"
    );
}
