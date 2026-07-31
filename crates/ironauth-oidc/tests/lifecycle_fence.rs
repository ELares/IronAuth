// SPDX-License-Identifier: MIT OR Apache-2.0

//! The tenant-lifecycle MINT fence (issue #46), against a real Postgres.
//!
//! A suspended (or offboarded) tenant must stop ISSUING. The control plane records the
//! serving decision in the scoped, data-plane-readable `environment_states` table; the
//! store-backed issuer registry consults it on EVERY resolution and fails closed for a
//! fenced scope.
//!
//! # What is enforced, and what is NOT (issue #448)
//!
//! This file used to open by saying a suspended tenant "must stop serving its data
//! plane". That is not what is enforced, and the difference is the whole of issue #448.
//!
//! ENFORCED, precisely: nothing is MINTED and nothing is SIGNED. The token endpoint
//! refuses every one of the five grants with `503 temporarily_unavailable`, JWKS and
//! discovery are fenced on the next request with no restart, and the authorization code
//! is NOT burned, so the same code mints once the scope resumes. Every one of those is
//! driven below.
//!
//! NOT enforced, equally precisely, and MEASURED on a store-backed harness with the
//! scope's serving state set to `suspended`:
//!
//! - `GET /authorize` for a consenting subject answers `303 See Other` and the redirect
//!   carries a fresh authorization code (`ac_...`).
//! - `POST /device_authorization` for a client permitted the device grant answers
//!   `200 OK` with a live `device_code`, a `user_code`, and both verification URIs. For a
//!   client NOT permitted that grant it answers `400 unauthorized_client`, which is the
//!   client-permission answer and not the fence, so the 200 above is the measurement that
//!   matters.
//! - Exchanging that code at the token endpoint answers `503 temporarily_unavailable`.
//!
//! The owner's decision is that refusing at the MINT is sufficient and the behavior
//! stays. The artifacts a suspended scope still issues are INERT: an authorization code
//! that cannot be exchanged and a device code that cannot be polled to a token are
//! bearer-shaped strings that unlock nothing, and they expire on their own.
//!
//! The cost is stated rather than hidden. A suspended tenant's user spends a FULL login
//! and consent journey, including entering credentials and approving scopes, and is
//! refused only at the last step, by a redirect target that fails rather than by anything
//! the authorization server said to them. An operator suspending a tenant should expect
//! that shape rather than a clean early refusal.
//!
//! The load-bearing property this proves is IMMEDIACY WITHOUT A RESTART: the scope
//! is served at least once first (so its issuer entry is CACHED in the live
//! registry), and only then suspended. A correct fence stops serving on the very
//! NEXT request against the SAME running node; a fence that only re-checks on a cold
//! cache load (the defect this test guards) would keep serving the cached entry
//! until the process restarts. The suite drives the JWKS and discovery surfaces and
//! shows: an active scope serves (200); once suspended it is fenced on the next
//! request with no restart (404); once resumed it serves again (200), the signing
//! key never touched (no data loss).
//!
//! It ALSO drives the TOKEN MINT (issue #406), which is the surface the fence exists
//! for and the one this doc used to assert rode along with the other two ("both funnel
//! through `IssuerRegistry::entry_for`, as does the token mint") while no test here
//! touched it. It does ride the same fence, and it now says so on the strength of
//! `a_suspended_scope_mints_no_token_from_an_outstanding_code` rather than on the
//! strength of a sentence. Its refusal answers in OAuth error shape rather than as a
//! 404, and it does not burn the code (the same code mints again once the scope
//! resumes).
//!
//! WHAT THAT REFUSAL SAYS is a decision, not an accident (issue #433). It is
//! `503 temporarily_unavailable` with a bounded `Retry-After`, because a suspension is
//! an operator state and not a fault: it was `500 server_error` only because the
//! issuer-entry lookup could not tell a fenced scope from a missing signing key. Those
//! are now separated at that lookup, and the four tests that hold the decision in
//! place are `a_suspended_scope_mints_no_token_from_an_outstanding_code` (the shape),
//! `every_token_endpoint_grant_answers_a_fenced_scope_the_same_way` (all FIVE grants,
//! not just the one the issue named, driven off `GrantType::ALL` so the set cannot
//! shrink, plus the suspended-versus-OFFBOARDED differential over a real
//! control-plane delete),
//! `a_fenced_scope_is_not_an_environment_existence_oracle` (the cost that shape
//! accepts), and `an_unrecognized_serving_status_fences_rather_than_serving` (the
//! fence read fails closed on a value it cannot name, which it did not used to). A
//! genuinely missing signing key STILL answers `500`, which
//! `a_missing_signing_key_still_answers_a_server_error` is there to keep true.
//!
//! It also drives the FAIL-CLOSED arm (`a_fence_read_error_fences_rather_than_serving`),
//! which was the other sentence this file was cited for and did not carry: flipping
//! the fence read's `Err(_)` arm from denying to permitting survived the whole
//! `ironauth-oidc` suite until that test existed.
//!
//! One test here drives the CONTROL PLANE ITSELF rather than seeding a serving state:
//! `a_restored_tenant_that_is_still_suspended_serves_nothing` runs the real suspend ->
//! grace delete -> restore sequence through the audited tenant repository and then asks
//! the data plane what it will serve (issue #432). The others deliberately set the
//! serving state directly, which is why the defect that test pins (a restore writing a
//! literal `active` over a suspended tenant's fence) was invisible to every one of them:
//! they never let a control-plane transition choose the state they assert on.
//!
//! Every test here MUST use `Harness::start_store_backed()`. The default
//! `Harness::start()` installs a static issuer registry that never reads
//! `environment_states`, so a suspended scope keeps serving on it and a lifecycle test
//! written against it passes while exercising nothing.

mod common;

use std::collections::BTreeSet;
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::{
    Harness, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, enc, form, form_field, json,
    location_param,
};
use ironauth_jose::{EmissionOptions, JwkSet, SigningKey, sign_jws};
use ironauth_oidc::{ClientAuthMethod, GrantType};
use ironauth_store::{
    ActingTenantRepo, AuthorizationCodeId, ClientId, CorrelationId, DeviceCodeId, EnvironmentId,
    OperatorId, RefreshTokenId, Scope, TenantId,
};
use sqlx::Row;

/// The offboarding retention window these tests restore inside. The harness clock is
/// frozen, so any window longer than zero keeps the restore on offer.
const RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// The simulated external issuer the jwt-bearer arm of the grant sweep trusts.
const EXTERNAL_ISSUER: &str = "https://workload.fence.test";

/// That issuer's external subject, mapped to a local principal for the sweep.
const EXTERNAL_SUBJECT: &str = "spiffe://cluster.test/ns/prod/sa/fenced";

/// The jwt-bearer probe assertion: syntactically a compact JWS, signed by nothing the
/// server trusts. The grant never reaches it (the presenting client is unknown first),
/// which is the ordering the oracle test is measuring.
const PROBE_ASSERTION: &str = "eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJodHRwczovL3Byb2JlLnRlc3QifQ.cHJvYmU";

/// Fetch the mounted JWKS for `scope` and return the HTTP status.
async fn jwks_status(harness: &Harness, scope: &Scope) -> StatusCode {
    jwks(harness, scope).await.0
}

/// Fetch the mounted JWKS for `scope` and return its status AND body, so a test that
/// claims a lifecycle round trip left the signing key alone can compare the published
/// key set itself rather than infer it from a 200.
async fn jwks(harness: &Harness, scope: &Scope) -> (StatusCode, String) {
    let uri = format!("/t/{}/e/{}/jwks.json", scope.tenant(), scope.environment());
    let (status, _headers, body) = harness
        .send(
            Request::builder()
                .method("GET")
                .uri(&uri)
                .body(Body::empty())
                .expect("request builds"),
        )
        .await;
    (status, body)
}

/// Fetch the appended-form discovery document for `scope` and return the status.
async fn discovery_status(harness: &Harness, scope: &Scope) -> StatusCode {
    let uri = format!(
        "/t/{}/e/{}/.well-known/openid-configuration",
        scope.tenant(),
        scope.environment()
    );
    status_of(harness, &uri).await
}

/// `GET uri` through the router and return only the status.
async fn status_of(harness: &Harness, uri: &str) -> StatusCode {
    let (status, _headers, _body) = harness
        .send(
            Request::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .expect("request builds"),
        )
        .await;
    status
}

/// Drive authorize to an OUTSTANDING authorization code for a fresh consenting
/// subject of the harness client, and return it unredeemed.
async fn outstanding_code(harness: &Harness) -> String {
    let client_id = harness.client_id().to_string();
    let subject = harness.seed_unique_user().await;
    harness.grant_consent(&subject, &client_id).await;
    let cookie = harness.session_cookie(&subject).await;
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
    );
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "authorize should redirect: {body}"
    );
    location_param(&headers, "code").expect("code in redirect")
}

/// Exchange `code` at the token endpoint as the harness public client.
async fn exchange(harness: &Harness, code: &str) -> (StatusCode, String) {
    let (status, _headers, body) = exchange_full(harness, code).await;
    (status, body)
}

/// [`exchange`], keeping the response HEADERS: the fenced refusal carries a
/// `Retry-After`, so a test that claims the whole answer is identical has to compare
/// the headers and not only the status and the body (issue #433).
async fn exchange_full(harness: &Harness, code: &str) -> (StatusCode, HeaderMap, String) {
    let body = form(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &harness.client_id().to_string()),
        ("code_verifier", PKCE_VERIFIER),
    ]);
    harness.token(&body).await
}

/// The `Retry-After` header value, or `None` when the response carries none.
fn retry_after(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
}

/// The COMPARABLE projection of a token-endpoint response: the status, the body, and
/// every header that a caller could read a difference out of.
///
/// The comparison an existence oracle would fail is over the whole answer, not over
/// the status line, so the headers ride along. `date`-like headers are absent from
/// these responses (the router sets none), so the projection is deterministic; if one
/// ever appears, this comparison starts failing LOUDLY rather than silently ignoring
/// the surface a leak could hide in.
fn comparable(status: StatusCode, headers: &HeaderMap, body: &str) -> String {
    let mut rendered: Vec<String> = headers
        .iter()
        .map(|(name, value)| format!("{name}: {}", value.to_str().unwrap_or("<non-ascii>")))
        .collect();
    rendered.sort();
    format!("{status}\n{}\n{body}", rendered.join("\n"))
}

/// Start an RFC 8628 device flow for `client_id`, returning `(device_code,
/// user_code)`. The client must already have the device grant enabled.
async fn start_device_flow(harness: &Harness, client_id: &str) -> (String, String) {
    let (status, _headers, body) = harness
        .post_form(
            "/device_authorization",
            &form(&[("client_id", client_id)]),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "device authorization: {body}");
    let started = json(&body);
    (
        started["device_code"]
            .as_str()
            .expect("device_code")
            .to_owned(),
        started["user_code"].as_str().expect("user_code").to_owned(),
    )
}

/// Sign a fresh human in and APPROVE the device flow identified by `user_code` at the
/// verification page, exactly as `crates/ironauth-oidc/tests/device.rs` drives it.
async fn approve_device_flow(harness: &Harness, user_code: &str) {
    let scope = harness.scope();
    let path = format!("/t/{}/e/{}/device", scope.tenant(), scope.environment());
    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;
    let (status, _headers, html) = harness
        .post_form(&path, &form(&[("user_code", user_code)]), Some(&cookie))
        .await;
    assert_eq!(status, StatusCode::OK, "device confirm page: {html}");
    let device_code_id =
        form_field(&html, "device_code_id").expect("the confirm page carries the flow handle");
    let (status, _headers, body) = harness
        .post_form(
            &path,
            &form(&[
                ("decision", "allow"),
                ("device_code_id", &device_code_id),
                ("user_code", user_code),
            ]),
            Some(&cookie),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "device approval: {body}");
}

/// Every grant [`GrantType::ALL`] declares, by its wire name.
///
/// The two grant lists in this file, `probe_forms` and `grant_answers`, each build
/// the set they actually drove and check it against this. Neither can silently
/// shrink (a dropped grant leaves the driven set short)
/// and neither can silently miss a grant added later (a sixth variant leaves the
/// driven set short the other way). That matters because both lists used to be
/// hand-written `&'static str` labels used only in panic messages: deleting the
/// device-code entry from both of them left the whole suite GREEN, measured, with
/// nothing but an `unused variable` warning that a real removal would not produce.
fn declared_grants() -> BTreeSet<&'static str> {
    GrantType::ALL.iter().map(|grant| grant.as_str()).collect()
}

/// The answer a `probe_forms` credential MUST reach, per grant: the status and the
/// OAuth error code.
///
/// This exists because the equality the oracle test asserts is satisfiable for the
/// WRONG reason. Two credentials that both died in the form parser also answer
/// identically, and the identical answer would then say nothing about the fence.
/// That is measured, not feared: replacing every generated handle in `probe_forms`
/// with a literal like `"not-a-refresh-token"` left the oracle test GREEN. What it
/// changed was the SHAPE, not the equality, because the refresh and device grants
/// drop from 401 to 400 once the handle no longer parses to a declared scope.
///
/// So the shapes below are the shapes of a probe that got PAST parsing: the four
/// client-authenticated grants reach client authentication and are refused THERE
/// (`401 invalid_client`), and the authorization-code grant reaches the code lookup
/// and is refused there (`400 invalid_grant`). Pinning them is what makes the
/// equality mean "both walked the same distance into the endpoint and hit the same
/// wall".
fn expected_probe_shape(grant: GrantType) -> (StatusCode, &'static str) {
    match grant {
        GrantType::AuthorizationCode => (StatusCode::BAD_REQUEST, "invalid_grant"),
        GrantType::RefreshToken
        | GrantType::ClientCredentials
        | GrantType::JwtBearer
        | GrantType::DeviceCode => (StatusCode::UNAUTHORIZED, "invalid_client"),
    }
}

/// One well-formed, UNREDEEMABLE credential per token-endpoint grant, built twice:
/// once declaring `suspended` and once declaring `ghost` (a scope that never
/// existed). Returned as `(grant, suspended_form, ghost_form)`.
///
/// Well formed matters, and [`expected_probe_shape`] is where that is MEASURED
/// rather than asserted in prose here. A credential the parser rejects outright
/// would make the two answers agree for a reason that has nothing to do with the
/// fence, and the test would pass while measuring nothing. Each of these parses,
/// declares its scope, and then resolves to no stored row, which is the state a real
/// prober would work from.
fn probe_forms(
    harness: &Harness,
    suspended: &Scope,
    ghost: &Scope,
) -> Vec<(GrantType, String, String)> {
    let env = harness.env();
    // A per-grant credential for one scope. The secret halves are inert filler: the
    // handle is what declares the scope and what the lookup misses on.
    let build = |scope: &Scope| {
        let client = ClientId::generate(env, scope).to_string();
        let code = AuthorizationCodeId::generate(env, scope).to_string();
        // The opaque wire forms are `<prefix><handle>~<secret>` (see
        // `crate::tokens::OPAQUE_REFRESH_TOKEN_PREFIX` and `device::DEVICE_CODE_PREFIX`).
        let refresh = format!("ira_rt_{}~cHJvYmU", RefreshTokenId::generate(env, scope));
        let device = format!("ira_dc_{}~cHJvYmU", DeviceCodeId::generate(env, scope));
        // Keyed by `GrantType`, and the caller checks the keys against
        // `GrantType::ALL`, so this list cannot lose a grant or miss a new one.
        vec![
            (
                GrantType::AuthorizationCode,
                form(&[
                    ("grant_type", GrantType::AuthorizationCode.as_str()),
                    ("code", &code),
                    ("redirect_uri", REDIRECT_URI),
                    ("client_id", &client),
                    ("code_verifier", PKCE_VERIFIER),
                ]),
            ),
            (
                GrantType::RefreshToken,
                form(&[
                    ("grant_type", GrantType::RefreshToken.as_str()),
                    ("refresh_token", &refresh),
                    ("client_id", &client),
                ]),
            ),
            (
                GrantType::ClientCredentials,
                form(&[
                    ("grant_type", GrantType::ClientCredentials.as_str()),
                    ("client_id", &client),
                    ("client_secret", "probe"),
                ]),
            ),
            (
                GrantType::JwtBearer,
                form(&[
                    ("grant_type", GrantType::JwtBearer.as_str()),
                    ("assertion", PROBE_ASSERTION),
                    ("client_id", &client),
                ]),
            ),
            (
                GrantType::DeviceCode,
                form(&[
                    ("grant_type", GrantType::DEVICE_CODE_URN),
                    ("device_code", &device),
                    ("client_id", &client),
                ]),
            ),
        ]
    };
    build(suspended)
        .into_iter()
        .zip(build(ghost))
        .map(|((grant, suspended_form), (_, ghost_form))| (grant, suspended_form, ghost_form))
        .collect()
}

/// One full set of token-endpoint credentials, one per grant, every one obtained
/// while the scope was HEALTHY, which is the only way a caller can hold one.
struct GrantCredentials {
    /// An outstanding, unredeemed authorization code.
    code: String,
    /// A live refresh token, opened by an earlier code exchange.
    refresh_token: String,
    /// A signed assertion from the registered external issuer.
    assertion: String,
    /// An APPROVED device code, so a poll with it is one that would have minted.
    device_code: String,
}

/// Obtain a fresh credential for every grant that mints at `POST /token`, against a
/// scope that is currently serving.
///
/// `jti` names this bundle's jwt-bearer assertion, which is single use, so two
/// bundles must not share one.
async fn grant_credentials(
    harness: &Harness,
    issuer_key: &SigningKey,
    jti: &str,
) -> GrantCredentials {
    let public_client = harness.client_id().to_string();

    // The first exchange opens a refresh family; the second code is left outstanding.
    let first_code = outstanding_code(harness).await;
    let (status, body) = exchange(harness, &first_code).await;
    assert_eq!(status, StatusCode::OK, "control exchange: {body}");
    let refresh_token = json(&body)["refresh_token"]
        .as_str()
        .expect("the code exchange opens a refresh family")
        .to_owned();
    let code = outstanding_code(harness).await;

    let assertion = sign_jws(
        issuer_key,
        &serde_json::to_vec(&serde_json::json!({
            "iss": EXTERNAL_ISSUER,
            "sub": EXTERNAL_SUBJECT,
            "aud": harness.issuer(),
            "exp": 3600,
            "iat": 0,
            "jti": jti,
        }))
        .expect("assertion claims"),
        &EmissionOptions::new(),
    )
    .expect("sign assertion");

    let (device_code, user_code) = start_device_flow(harness, &public_client).await;
    approve_device_flow(harness, &user_code).await;

    GrantCredentials {
        code,
        refresh_token,
        assertion,
        device_code,
    }
}

/// Present every token-endpoint credential in `credentials` once, and return each
/// grant's COMPARABLE answer.
///
/// One entry per grant, keyed by [`GrantType`]; the caller checks the keys against
/// [`GrantType::ALL`], so a grant cannot quietly drop out of the sweep.
async fn grant_answers(
    harness: &Harness,
    basic: &str,
    credentials: &GrantCredentials,
) -> Vec<(GrantType, String)> {
    let public_client = harness.client_id().to_string();
    let mut answers: Vec<(GrantType, String)> = Vec::new();

    let (status, headers, body) = exchange_full(harness, &credentials.code).await;
    answers.push((
        GrantType::AuthorizationCode,
        comparable(status, &headers, &body),
    ));

    let (status, headers, body) = harness
        .token(&form(&[
            ("grant_type", GrantType::RefreshToken.as_str()),
            ("refresh_token", &credentials.refresh_token),
            ("client_id", &public_client),
        ]))
        .await;
    answers.push((GrantType::RefreshToken, comparable(status, &headers, &body)));

    let (status, headers, body) = harness
        .token_with_auth(
            &form(&[("grant_type", GrantType::ClientCredentials.as_str())]),
            Some(basic),
        )
        .await;
    answers.push((
        GrantType::ClientCredentials,
        comparable(status, &headers, &body),
    ));

    let (status, headers, body) = harness
        .token(&form(&[
            ("grant_type", GrantType::JwtBearer.as_str()),
            ("assertion", &credentials.assertion),
            ("client_id", &public_client),
        ]))
        .await;
    answers.push((GrantType::JwtBearer, comparable(status, &headers, &body)));

    // The device grant paces itself against the issued interval, so a poll at the
    // same frozen instant would be `slow_down` and would never reach the mint.
    harness.clock().advance(Duration::from_secs(6));
    let (status, headers, body) = harness
        .token(&form(&[
            ("grant_type", GrantType::DEVICE_CODE_URN),
            ("device_code", &credentials.device_code),
            ("client_id", &public_client),
        ]))
        .await;
    answers.push((GrantType::DeviceCode, comparable(status, &headers, &body)));

    answers
}

/// Set the data-plane serving state of `scope`, exactly as a control-plane
/// suspend/resume/delete cascade writes it. The control-plane transition logic
/// itself is proven in the store crate's tenant-lifecycle tests; here we only need
/// the precondition set.
async fn set_serving(harness: &Harness, scope: &Scope, status: &str) {
    harness
        .db()
        .set_environment_serving_state(*scope, status)
        .await;
}

/// The operator that owns `scope`'s tenant, read as the owner: the harness seeds the
/// operator -> tenant -> environment chain directly and keeps the operator id to
/// itself, and the control-plane tenant repository is addressed per operator.
async fn operator_of(harness: &Harness, scope: &Scope) -> OperatorId {
    let raw: String = sqlx::query("SELECT operator_id FROM tenants WHERE id = $1")
        .bind(scope.tenant().to_string())
        .fetch_one(harness.db().owner_pool())
        .await
        .expect("the harness tenant row is present")
        .get("operator_id");
    OperatorId::parse(&raw).expect("operator id parses")
}

/// The acting, audited control-plane tenant repository for `operator`, over the
/// CONTROL-plane store, exactly as the management API reaches it.
fn tenants(harness: &Harness, operator: OperatorId) -> ActingTenantRepo<'_> {
    harness
        .db()
        .control_store()
        .management()
        .acting(
            harness.db().test_actor(harness.env()),
            CorrelationId::generate(harness.env()),
        )
        .tenants(operator)
}

#[tokio::test]
async fn a_restored_tenant_that_is_still_suspended_serves_nothing() {
    // Issue #432, at the surface the fence exists for. The other tests here set the
    // serving state directly; this one drives the REAL control-plane lifecycle calls
    // (suspend -> grace delete -> restore) and then asks the data plane what it will
    // serve. The defect: `restore` wrote a literal `active` serving state for every
    // environment, so a tenant whose `tenants.status` still read `suspended` came back
    // serving JWKS and discovery with nobody having lifted the suspension.
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    let operator = operator_of(&harness, &scope).await;

    // The control: active and serving, which also WARMS the registry cache. The
    // published key set is kept, so the claim that the round trip below never touches
    // the signing key is carried by a comparison rather than by a 200.
    let (status, published_keys) = jwks(&harness, &scope).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an active environment serves its JWKS"
    );

    // Suspend through the control plane: fenced on the next request.
    tenants(&harness, operator)
        .suspend(harness.env(), &scope.tenant(), None)
        .await
        .expect("suspend");
    assert_eq!(
        jwks_status(&harness, &scope).await,
        StatusCode::NOT_FOUND,
        "a suspended tenant is fenced off the JWKS surface"
    );

    // Grace-delete and then RESTORE inside the retention window. The restore undoes
    // the delete; it must not undo the suspension too.
    tenants(&harness, operator)
        .delete(harness.env(), &scope.tenant())
        .await
        .expect("grace delete");
    tenants(&harness, operator)
        .restore(harness.env(), &scope.tenant(), RETENTION, None)
        .await
        .expect("restore in window");

    assert_eq!(
        jwks_status(&harness, &scope).await,
        StatusCode::NOT_FOUND,
        "a restored tenant whose status is still suspended serves no JWKS"
    );
    assert_eq!(
        discovery_status(&harness, &scope).await,
        StatusCode::NOT_FOUND,
        "and no discovery document: the restore did not lift the suspension"
    );

    // The explicit RESUME is what lifts it, and it still does after a restore: the
    // fence a restore preserves is not a permanent one.
    tenants(&harness, operator)
        .resume(harness.env(), &scope.tenant(), None)
        .await
        .expect("resume");
    let (status, keys_after) = jwks(&harness, &scope).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a resumed tenant serves its JWKS again"
    );
    assert_eq!(
        keys_after, published_keys,
        "and serves the SAME key set: suspend, delete, restore, and resume never \
         touched the signing key"
    );
    assert_eq!(
        discovery_status(&harness, &scope).await,
        StatusCode::OK,
        "and serves discovery again"
    );
}

#[tokio::test]
async fn a_suspended_scope_is_fenced_on_the_next_request_without_a_restart() {
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();

    // Serve the scope FIRST, so its issuer entry is now cached in the live registry.
    // Both surfaces are 200 for an active, provisioned environment.
    assert_eq!(
        jwks_status(&harness, &scope).await,
        StatusCode::OK,
        "an active environment serves its JWKS"
    );
    assert_eq!(
        discovery_status(&harness, &scope).await,
        StatusCode::OK,
        "an active environment serves its discovery document"
    );

    // Suspend the scope (a control-plane suspend cascade). NO restart: the SAME
    // running node, with the entry still cached, must stop serving on the next
    // request. This is the assertion the cached-fast-path defect fails: without the
    // per-resolution fence the cached entry keeps serving JWKS/discovery/token.
    set_serving(&harness, &scope, "suspended").await;
    assert_eq!(
        jwks_status(&harness, &scope).await,
        StatusCode::NOT_FOUND,
        "a suspended scope is fenced off the JWKS surface on the very next request"
    );
    assert_eq!(
        discovery_status(&harness, &scope).await,
        StatusCode::NOT_FOUND,
        "a suspended scope is fenced off the discovery surface on the very next request"
    );

    // Resume the scope: it serves again on the next request, still no restart, and
    // the signing key was never touched (no data loss).
    set_serving(&harness, &scope, "active").await;
    assert_eq!(
        jwks_status(&harness, &scope).await,
        StatusCode::OK,
        "a resumed scope serves its JWKS again with no data loss"
    );
    assert_eq!(
        discovery_status(&harness, &scope).await,
        StatusCode::OK,
        "a resumed scope serves its discovery document again"
    );
}

#[tokio::test]
async fn a_suspended_scope_mints_no_token_from_an_outstanding_code() {
    // The TOKEN MINT, which this file's own module doc has always named as riding the
    // same fence while the file drove only JWKS and discovery (issue #406). It is the
    // surface that matters most and it was the one not measured, so it is measured
    // here. This is also the ENVIRONMENT and TENANT half of the effective-resolution
    // liveness question: those two dimensions are deliberately NOT fenced in the
    // organization closure, on the grounds that a deactivated scope must not issue a
    // token at all rather than issue a role-less one. That grounds is only sound if
    // this passes.
    //
    // # THE HARNESS TRAP, which is the reason to read this comment before writing a
    // # lifecycle test of your own
    //
    // This MUST use `Harness::start_store_backed()`. The default `Harness::start()`
    // installs a STATIC issuer registry that never consults `environment_states`, so a
    // suspended scope on that harness serves a full 200 with a signed, claim-bearing
    // access token and every assertion below passes in reverse. A lifecycle test
    // written on the default harness is green, silent, and worthless: it reports that
    // the fence works while exercising no fence at all. That was measured on this
    // exact scenario before this test was written, which is why it is written down.
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();

    // The control: an active scope mints from an outstanding code, so a refusal below
    // is attributable to the fence rather than to the fixture or the store-backed
    // wiring.
    let code = outstanding_code(&harness).await;
    let (status, body) = exchange(&harness, &code).await;
    assert_eq!(status, StatusCode::OK, "active scope exchange: {body}");
    assert!(
        json(&body)["access_token"].is_string(),
        "an active scope mints an access token"
    );

    // Suspend, with the issuer entry now warm in the registry from the exchange above.
    // The next exchange must refuse on the SAME running node, no restart, exactly as
    // the JWKS and discovery surfaces do.
    let code = outstanding_code(&harness).await;
    set_serving(&harness, &scope, "suspended").await;
    let (status, headers, body) = exchange_full(&harness, &code).await;
    // THE DECIDED SHAPE (issue #433). This assertion pins a DECISION, and the earlier
    // version of it pinned an ACCIDENT: the refusal used to be `500 server_error`,
    // because the issuer-entry lookup could not tell "fenced" from "no signing key"
    // and the latter genuinely is a fault. The two are now distinguished at that call
    // site, and an administrative suspension answers what is TRUE of it:
    //
    // - `503`, because the server is declining to serve this environment right now,
    //   not failing at it. `500` told a relying party to retry forever and charged a
    //   deliberate operator action to the error-rate budget of a fault.
    // - `temporarily_unavailable` rather than a 4xx: `invalid_grant` would assert
    //   something FALSE about the code, which is still perfectly valid (the resume
    //   below redeems this very code), and a conforming client would discard it.
    // - a bounded `Retry-After`, because "come back later" without a delay is an
    //   invitation to a retry storm.
    //
    // What it does NOT resolve, stated so the next reader does not have to rediscover
    // it: 503 is still 5xx, so this makes the operator action DISTINGUISHABLE from a
    // fault rather than removing it from the 5xx class. And an OFFBOARDED environment,
    // for which "temporarily" is literally false, answers this SAME 503 on purpose,
    // because an answer that separated permanent from temporary would be an oracle
    // over lifecycle state (see `a_fenced_scope_is_not_an_environment_existence_oracle`,
    // which pins the cost that ruling accepts).
    //
    // This is also the half of issue #406's contradiction that moved. Its sibling,
    // `a_soft_deleted_user_resolves_to_nothing_on_all_three_projections` in
    // `crates/ironauth-store/tests/org_assignments.rs`, reads a deleted user as an
    // operator state rather than a store fault; this file used to read the same class
    // of state as a fault. They now agree.
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "a suspended scope refuses the exchange as unavailable, not as a fault: {body}"
    );
    assert_eq!(json(&body)["error"], "temporarily_unavailable");
    assert_eq!(
        retry_after(&headers),
        Some("60"),
        "the refusal carries the bounded Retry-After a client should honor"
    );
    assert!(
        json(&body).get("access_token").is_none(),
        "a suspended scope mints no access token"
    );
    assert!(
        json(&body).get("id_token").is_none(),
        "and no id token: the fence is upstream of the signing, not a claim filter"
    );

    // Resumed. The refused exchange did NOT consume the code: this fence sits at the
    // issuer-entry lookup inside `mint_tokens`, and the whole mint runs BEFORE the
    // atomic redeem precisely so a signing failure never burns a code. So the SAME
    // code, unredeemed, is presented again here rather than a fresh one, which turns
    // that claim from a comment into an assertion.
    set_serving(&harness, &scope, "active").await;
    let (status, body) = exchange(&harness, &code).await;
    assert_eq!(status, StatusCode::OK, "resumed scope exchange: {body}");
    assert!(
        json(&body)["access_token"].is_string(),
        "a resumed scope mints again from the very code the fence refused, its signing \
         key never touched and that code never burned"
    );
}

// Five grants, each with its own fixture, driven against ONE fence in ONE order:
// gather every credential while healthy, raise the fence once, then compare all five
// answers. Splitting it would need the fixtures to be rebuilt per grant and would lose
// the cross-grant comparison, which is the assertion that matters most here.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn every_token_endpoint_grant_answers_a_fenced_scope_the_same_way() {
    // THE SWEEP (issue #433). The issue names `mint_tokens`, which serves the
    // authorization-code grant, and the named handler is not the complete set: FIVE
    // grants reach an issuer-entry lookup on `POST /token`, and a fix applied to one
    // of them would leave four minting paths answering a suspension as a fault.
    //
    // The five were enumerated from the exhaustive `match GrantType::parse(..)` in
    // `crate::token::exchange` (whose arms are `GrantType::ALL`) and cross-checked
    // against every `issuer_entry` / `entry_for` call site in `ironauth-oidc/src`.
    // The other call sites found that way are NOT token-endpoint grants (authorize's
    // front-channel ID token, the DISCOVERY document, FedCM, back-channel logout,
    // client registration, the shared environment-guardrail and banner lookups the
    // hosted pages read, and the access-token/logout-hint VERIFY paths), and they
    // keep their own shapes.
    //
    // That census used to be a claim this file could not check, because the grants
    // were hand-written string labels: deleting one left the suite green. It is now
    // DRIVEN off `GrantType::ALL` and checked against it below, so an undriven grant
    // and a sixth grant added later both fail here.
    //
    // Every credential below is obtained while the scope is healthy, because that is
    // the only way to hold one: a caller who has none never reaches this refusal at
    // all (`a_fenced_scope_is_not_an_environment_existence_oracle`).
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    let public_client = harness.client_id().to_string();
    let operator = operator_of(&harness, &scope).await;

    // A confidential client for the client-credentials grant.
    let (confidential, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let basic = format!(
        "Basic {}",
        STANDARD.encode(format!("{confidential}:{secret}"))
    );

    // A registered external issuer and subject mapping for the jwt-bearer grant.
    let issuer_key = SigningKey::ed25519_from_seed(Some("fence".to_owned()), &[9_u8; 32])
        .expect("external issuer key");
    let jwks = JwkSet::from_signing_keys([&issuer_key])
        .expect("jwk set")
        .to_json()
        .expect("jwks json");
    harness
        .register_external_issuer(EXTERNAL_ISSUER, Some(&jwks), None, None, true)
        .await;
    harness
        .create_subject_mapping(EXTERNAL_ISSUER, EXTERNAL_SUBJECT, None, None, "usr_fenced")
        .await;

    // The device grant, enabled on the public client.
    harness
        .enable_device_grant(
            harness.client_id(),
            "authorization_code urn:ietf:params:oauth:grant-type:device_code",
            None,
        )
        .await;

    // The first bundle: one live credential per grant, all five taken while serving.
    let suspended_credentials = grant_credentials(&harness, &issuer_key, "jti-fence-suspend").await;

    // The fence goes up with every credential already in hand and the issuer entry
    // warm in the registry.
    set_serving(&harness, &scope, "suspended").await;

    let suspended_answers = grant_answers(&harness, &basic, &suspended_credentials).await;

    for (grant, answer) in &suspended_answers {
        let grant = grant.as_str();
        assert!(
            answer.starts_with("503 Service Unavailable\n"),
            "the {grant} grant must answer a fenced scope as unavailable, not as a \
             fault or a bad request: {answer}"
        );
        assert!(
            answer.contains("retry-after: 60"),
            "the {grant} grant's refusal carries the bounded Retry-After: {answer}"
        );
        assert!(
            answer.contains(r#""error":"temporarily_unavailable""#),
            "the {grant} grant names the refusal temporarily_unavailable: {answer}"
        );
        assert!(
            !answer.contains("access_token"),
            "the {grant} grant mints nothing for a fenced scope: {answer}"
        );
        // THE REFUSAL NAMES NO LIFECYCLE STATE. `crate::error`'s module doc calls
        // this property (1) and "load bearing", and the THREAT-MODEL row asserts it,
        // and until this loop existed NOTHING measured it: changing the refusal's
        // description to "this environment has been suspended by an operator; retry
        // later" left this test 8 passed, 0 failed. A wire answer that names the
        // state is an oracle over lifecycle even when the status code does not vary.
        let lowered = answer.to_ascii_lowercase();
        for named in ["suspend", "offboard", "delete", "unknown", "fenced"] {
            assert!(
                !lowered.contains(named),
                "the {grant} grant's refusal must not name a lifecycle state, and it \
                 says {named}: {answer}"
            );
        }
    }
    // And they are IDENTICAL to one another, headers included: which grant was
    // attempted is not readable out of the refusal either.
    let (first_grant, first_answer) = &suspended_answers[0];
    for (grant, answer) in &suspended_answers[1..] {
        assert_eq!(
            answer,
            first_answer,
            "the {} grant's fenced refusal differs from the {} grant's",
            grant.as_str(),
            first_grant.as_str()
        );
    }
    // The census, as a measurement: exactly the grants `GrantType::ALL` declares were
    // driven, no more and no fewer.
    let driven: BTreeSet<&str> = suspended_answers
        .iter()
        .map(|(grant, _)| grant.as_str())
        .collect();
    assert_eq!(
        driven,
        declared_grants(),
        "the sweep must drive EVERY grant GrantType::ALL declares: a grant missing \
         here is a minting path whose fenced answer nothing checks"
    );

    // Resumed: every one of those credentials still works, so the fence refused them
    // without spending any of them. This is the sweep's version of "the code is not
    // burned", and it is what makes the refusal safe to retry after the suspension.
    set_serving(&harness, &scope, "active").await;
    let (status, body) = exchange(&harness, &suspended_credentials.code).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the code the fence refused still exchanges once resumed: {body}"
    );
    let (status, _headers, body) = harness
        .token(&form(&[
            ("grant_type", GrantType::RefreshToken.as_str()),
            ("refresh_token", &suspended_credentials.refresh_token),
            ("client_id", &public_client),
        ]))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the refresh token the fence refused was not rotated or revoked by it: {body}"
    );
    let (status, _headers, body) = harness
        .token_with_auth(
            &form(&[("grant_type", GrantType::ClientCredentials.as_str())]),
            Some(&basic),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "client credentials resume: {body}");
    harness.clock().advance(Duration::from_secs(6));
    let (status, _headers, body) = harness
        .token(&form(&[
            ("grant_type", GrantType::DEVICE_CODE_URN),
            ("device_code", &suspended_credentials.device_code),
            ("client_id", &public_client),
        ]))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the approved device flow the fence refused was not consumed by it: {body}"
    );

    // THE OFFBOARD DIFFERENTIAL. "Suspended and offboarded render identically" is
    // asserted in four prose places (this file, `crate::error`'s module doc, the
    // changelog, and the THREAT-MODEL row) and it used to rest entirely on reading
    // two repository methods and noticing both write `serving_status = 'suspended'`.
    // Nothing drove a real offboard to `/token`. This does: a second bundle of live
    // credentials, then the REAL audited control-plane tenant delete, then the same
    // five grants again. Byte for byte the same answers, or the refusal is an oracle
    // over lifecycle state and the endless-retry cost recorded above is not the cost
    // that was actually accepted.
    let offboarded_credentials =
        grant_credentials(&harness, &issuer_key, "jti-fence-offboard").await;
    tenants(&harness, operator)
        .delete(harness.env(), &scope.tenant())
        .await
        .expect("grace delete");
    let offboarded_answers = grant_answers(&harness, &basic, &offboarded_credentials).await;
    assert_eq!(
        offboarded_answers, suspended_answers,
        "an OFFBOARDED environment must answer every grant exactly as a SUSPENDED one \
         does, headers included"
    );
}

#[tokio::test]
async fn a_fenced_scope_is_not_an_environment_existence_oracle() {
    // THE COST OF THE 503, pinned (issue #433). The refusal above is only safe if it
    // cannot be used to ask "does this environment exist", and the ruling that closes
    // that question is: a scope that NEVER EXISTED must answer byte for byte what a
    // suspended one answers.
    //
    // The property that delivers it is an ORDERING one, and it is the thing a later
    // refactor is most likely to break: every grant validates the presented credential
    // BEFORE it resolves an issuer entry, so the 503 is reachable only by a caller who
    // already holds a credential this very environment minted. To everyone else, a
    // suspended environment and one that was never created are the same wall. Hoisting
    // the fence check earlier (to "fail fast", say) would answer 503 for the suspended
    // scope and 400 for the unknown one, and hand out exactly the two-valued answer
    // this test exists to deny.
    //
    // THE ACCEPTED COST, and it lands somewhere slightly different from where it was
    // expected to, which is worth writing down because the difference is measurable
    // here rather than arguable. The cost was anticipated as "a mistyped or stale
    // issuer will present as temporarily unavailable forever". A STALE one does: a
    // client still holding a credential from an OFFBOARDED environment is told to
    // retry, and retrying will never succeed, because offboarding is permanent and
    // deliberately answers the same 503 as a suspension. A MISTYPED one does NOT,
    // and the loop below is what shows it: an environment id nobody ever created
    // cannot mint a credential, so a caller naming it never reaches the 503 at all
    // and gets this uniform 4xx instead (and its discovery document, the surface an
    // integrator actually configures against, answers 404, which this test now
    // ISSUES rather than claiming). The endless-retry burden
    // is therefore real but narrower than "any typo": it falls on holders of
    // credentials from an environment that was real and is now fenced.
    //
    // Both were accepted knowingly, because the alternative (an answer that separates
    // "not serving" from "never existed") is an enumeration oracle over every
    // deployment's tenant list.
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    let env = harness.env();

    // A scope that never existed: well formed, in the right shape, and belonging to no
    // tenant this deployment ever created.
    let ghost = Scope::new(TenantId::generate(env), EnvironmentId::generate(env));

    // The control: the real scope is REAL, which is what stops this from comparing two
    // uniformly broken answers and calling them alike.
    let real_code = outstanding_code(&harness).await;
    let (status, body) = exchange(&harness, &real_code).await;
    assert_eq!(status, StatusCode::OK, "the real scope serves: {body}");

    set_serving(&harness, &scope, "suspended").await;

    // A credential holder DOES see the difference, and that is the point: the 503 is
    // an answer to someone the environment already knows.
    let held = outstanding_code(&harness).await;
    let (status, _headers, body) = exchange_full(&harness, &held).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "the fenced scope answers a HELD credential with the 503: {body}"
    );

    // The surface an integrator actually configures against, measured rather than
    // asserted: BOTH scopes answer the same 404 on discovery, so the document that
    // would tell a prober whether an environment exists tells them nothing either.
    assert_eq!(
        discovery_status(&harness, &ghost).await,
        StatusCode::NOT_FOUND,
        "a scope that never existed has no discovery document"
    );
    assert_eq!(
        discovery_status(&harness, &scope).await,
        StatusCode::NOT_FOUND,
        "and neither does the suspended one: discovery is not the oracle either"
    );

    // Everyone else sees one wall. Each probe below is well formed for its grant and
    // unredeemable, presented once against the SUSPENDED scope and once against the
    // scope that never existed.
    let mut driven: BTreeSet<&str> = BTreeSet::new();
    for (grant, suspended_form, ghost_form) in probe_forms(&harness, &scope, &ghost) {
        driven.insert(grant.as_str());
        let label = grant.as_str();
        let (status, headers, body) = harness.token(&suspended_form).await;
        let suspended_answer = comparable(status, &headers, &body);
        // The SHAPE first, because equality alone is satisfied by two credentials
        // that both died in the form parser, and then the equality would be measuring
        // the parser rather than the fence. See `expected_probe_shape`.
        let (expected_status, expected_error) = expected_probe_shape(grant);
        assert_eq!(
            status, expected_status,
            "the {label} probe must be well formed enough to reach the check that \
             refuses it: {suspended_answer}"
        );
        assert_eq!(
            json(&body)["error"],
            expected_error,
            "and to be refused BY that check: {suspended_answer}"
        );
        let (status, headers, body) = harness.token(&ghost_form).await;
        let ghost_answer = comparable(status, &headers, &body);
        assert_eq!(
            suspended_answer, ghost_answer,
            "the {label} grant must answer a suspended environment and one that never \
             existed identically, headers included"
        );
        assert!(
            !suspended_answer.contains("temporarily_unavailable"),
            "and it must not be the fenced refusal: reaching that without a credential \
             would BE the oracle ({label})"
        );
    }
    assert_eq!(
        driven,
        declared_grants(),
        "every grant GrantType::ALL declares must be probed: an unprobed grant is a \
         grant whose answer to a never-existed scope nothing compares"
    );
}

#[tokio::test]
async fn a_missing_signing_key_still_answers_a_server_error() {
    // THE OTHER HALF of issue #433, and the one a careless change breaks: an
    // environment that is SERVING but has no signing key is a genuine FAULT, and it
    // must keep its `500 server_error`. If the fenced 503 were widened to cover every
    // absent issuer entry, a real outage (an unprovisioned environment, a key deleted
    // out from under a live scope, a cross-tenant load that reads zero rows) would
    // start telling relying parties to come back in a minute, which is worse than the
    // defect this issue set out to correct.
    //
    // The environment here is NOT fenced: `environment_states` says nothing about it,
    // which reads as serving. Only its keys are gone.
    let harness = Harness::start_store_backed().await;
    let code = outstanding_code(&harness).await;

    // The authorization leg does not resolve an issuer entry, so the registry is still
    // cold here and the exchange below performs a real load rather than serving a
    // cached entry. That is measured, not assumed: with the keys present the same
    // sequence mints (the other tests in this file), and with them gone it must not.
    harness
        .db()
        .execute_owner_sql("DELETE FROM signing_keys")
        .await;

    let (status, headers, body) = exchange_full(&harness, &code).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "a serving environment with no signing key is a fault, not a suspension: {body}"
    );
    assert_eq!(json(&body)["error"], "server_error");
    assert_eq!(
        retry_after(&headers),
        None,
        "and it carries no Retry-After: there is no delay after which a missing key \
         fixes itself"
    );
    assert!(
        json(&body).get("access_token").is_none(),
        "nothing is minted without a signing key"
    );
}

#[tokio::test]
async fn a_deleted_scope_stops_serving_immediately() {
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();

    // Warm the cache with a served request.
    assert_eq!(jwks_status(&harness, &scope).await, StatusCode::OK);

    // A tenant delete (offboard) fences every environment by writing the suspended
    // serving state, exactly as suspend does. The fenced scope stops serving at once,
    // no restart, on both surfaces.
    set_serving(&harness, &scope, "suspended").await;
    assert_eq!(
        jwks_status(&harness, &scope).await,
        StatusCode::NOT_FOUND,
        "a deleted (fenced) scope stops serving its JWKS immediately"
    );
    assert_eq!(
        discovery_status(&harness, &scope).await,
        StatusCode::NOT_FOUND,
        "a deleted (fenced) scope stops serving its discovery immediately"
    );
}

#[tokio::test]
async fn a_fence_read_error_fences_rather_than_serving() {
    // The FAIL-CLOSED half of the fence (issue #406). The fence read maps a store read
    // error on `environment_states` to a refusal, and that arm was previously claimed
    // by the census and pinned by NOTHING: flipping it from denying to permitting
    // survived the entire `ironauth-oidc` suite, measured. It is the arm that matters
    // most operationally, because a suspension enforced only while the database is
    // healthy is not a suspension: a pool timeout on the fence read would let a
    // suspended or offboarded tenant serve for as long as the blip lasts.
    //
    // The token refusal here is still `500 server_error`, and that is now a DECISION
    // rather than the shared shape it used to be (issue #433). A fenced scope answers
    // `503 temporarily_unavailable`, but an UNREADABLE fence is not a fence: the
    // serving state was never read, so the server does not know whether an operator
    // suspended anything. What it does know is that its database did not answer, which
    // is a fault, so it says so. Serving is denied either way, which is the property
    // this test exists for.
    //
    // The blip is induced the same way
    // `a_transient_store_error_does_not_negative_cache_a_real_scope` induces one in
    // `crates/ironauth-oidc/tests/issuer_registry.rs`: RENAME the table out from under
    // the read, so the SELECT errors while everything else stays healthy. Rename
    // rather than drop, so the relation's OID survives and restoring it invalidates no
    // cached plan.
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();

    // The controls, both taken while the scope is healthy and ACTIVE, so a refusal
    // below is attributable to the read error and not to a fence state or a fixture.
    // Taking them first also WARMS the registry cache, which is what makes the
    // assertion sharp: the fence has to beat a fresh cached entry, not merely a cold
    // load that would fail anyway.
    let code = outstanding_code(&harness).await;
    assert_eq!(jwks_status(&harness, &scope).await, StatusCode::OK);
    let (status, body) = exchange(&harness, &code).await;
    assert_eq!(status, StatusCode::OK, "healthy active scope: {body}");

    // The blip: the fence read now errors. Everything else (the signing keys, the
    // guardrails, the codes) is untouched and healthy.
    let code = outstanding_code(&harness).await;
    harness
        .db()
        .execute_owner_sql("ALTER TABLE environment_states RENAME TO environment_states_hidden")
        .await;

    assert_eq!(
        jwks_status(&harness, &scope).await,
        StatusCode::NOT_FOUND,
        "a fence read error denies serving rather than permitting it"
    );
    let (status, body) = exchange(&harness, &code).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "and the token mint refuses too: {body}"
    );
    assert_eq!(json(&body)["error"], "server_error");
    assert!(
        json(&body).get("access_token").is_none(),
        "no access token is minted while the fence cannot be read"
    );

    // The blip clears. The scope serves again on the VERY NEXT request, so failing
    // closed here is a refusal for the duration of the fault and not a self-inflicted
    // outage that outlives it.
    harness
        .db()
        .execute_owner_sql("ALTER TABLE environment_states_hidden RENAME TO environment_states")
        .await;
    assert_eq!(
        jwks_status(&harness, &scope).await,
        StatusCode::OK,
        "the healthy scope serves again on the next request"
    );
    let code = outstanding_code(&harness).await;
    let (status, body) = exchange(&harness, &code).await;
    assert_eq!(status, StatusCode::OK, "and mints again: {body}");
    assert!(
        json(&body)["access_token"].is_string(),
        "the fence read error cost the scope nothing beyond the blip"
    );
}

#[tokio::test]
async fn an_unrecognized_serving_status_fences_rather_than_serving() {
    // THE THIRD ARM OF THE FENCE READ, which nothing held before this test and which
    // pointed the WRONG WAY (issue #433). `environment_state()` maps the stored
    // `serving_status` string with `"suspended" => Suspended, _ => Active`, so a
    // value this build does not recognize was SERVED. That is measured, not
    // theorized: dropping the CHECK constraint and writing `'offboarding'` (exactly
    // what this test does below) used to answer `200` with a full access token, ID
    // token, and refresh token.
    //
    // Nothing reaches that today. The `environment_states_serving_status_valid` CHECK
    // admits only 'active' and 'suspended', the data-plane role has no write grant on
    // the table at all, and this test has to take a wrecking ball to the schema to
    // produce the input. So this is not a live hole and was not one before.
    //
    // It is a POSTURE defect, and the posture is written down two layers up: the
    // fence reads FAIL CLOSED, the type that carries its outcome says so in its own
    // documentation, and this change's whole purpose is precision about what that
    // read returned. A read that silently SERVES a value it could not interpret
    // contradicts all of that, and the way it would come true is ordinary: someone
    // adds a lifecycle state to the CHECK constraint and does not add it here, and
    // the environment it names keeps minting tokens.
    //
    // So the unknown value is fenced, and it is fenced rather than reported as
    // UNREADABLE because of who can write it. Only the control plane can, and only a
    // value its own CHECK admits, so a string here is a deliberate administrative
    // state this build is too old to name. It is not a broken database. Answering it
    // like a suspension is both the true statement and the one that keeps the
    // fenced refusal uniform: a future state renders exactly as suspended and
    // offboarded do, and adds no new distinguishable answer.
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();

    // The control: serving, and minting, before the schema is touched.
    let code = outstanding_code(&harness).await;
    let (status, body) = exchange(&harness, &code).await;
    assert_eq!(status, StatusCode::OK, "active scope exchange: {body}");

    // The only way to produce the input: remove the constraint that is the sole
    // reason no such value exists, then write one. Owner-only surgery on a throwaway
    // database, exactly as the fence-read-error test renames a table out from under a
    // live read.
    let code = outstanding_code(&harness).await;
    harness
        .db()
        .execute_owner_sql(
            "ALTER TABLE environment_states \
             DROP CONSTRAINT environment_states_serving_status_valid",
        )
        .await;
    set_serving(&harness, &scope, "offboarding").await;

    let (status, headers, body) = exchange_full(&harness, &code).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "a serving status this build cannot name must FENCE, not serve: {body}"
    );
    assert_eq!(json(&body)["error"], "temporarily_unavailable");
    assert_eq!(
        retry_after(&headers),
        Some("60"),
        "and it is the same refusal a suspension gets, down to the delay: a state \
         this build is too old to name must not be distinguishable on the wire"
    );
    assert!(
        json(&body).get("access_token").is_none(),
        "nothing is minted for an unrecognized serving status"
    );
    assert!(
        json(&body).get("refresh_token").is_none(),
        "and no refresh token: this used to hand out a whole token set"
    );

    // The other two surfaces fence on it too, for the same reason and by the same
    // read, so the posture is uniform rather than token-endpoint-only.
    assert_eq!(
        jwks_status(&harness, &scope).await,
        StatusCode::NOT_FOUND,
        "the JWKS surface fences an unrecognized serving status"
    );
    assert_eq!(
        discovery_status(&harness, &scope).await,
        StatusCode::NOT_FOUND,
        "and so does discovery"
    );
}
