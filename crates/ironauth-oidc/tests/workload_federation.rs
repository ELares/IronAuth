// SPDX-License-Identifier: MIT OR Apache-2.0

//! Workload identity federation through the OPERATOR-FACING path (issue #126).
//!
//! The sibling `jwt_bearer.rs` proves the RFC 7523 grant enforces what it is configured
//! with. It registers every trust anchor by calling the store repository directly, which
//! no operator can do, so it says nothing about whether the feature can be TURNED ON.
//!
//! That distinction was not academic. Measured on 2026-08-23, `external_assertion_issuers`
//! and `external_assertion_subject_mappings` were reachable from the repository layer and
//! from nowhere else: no management route, no `IaC` resource, no config field, no CLI
//! command. The enforcement half shipped and was well covered while nothing could grant
//! it, which is a defect class this repository has hit before.
//!
//! So these tests drive the management HTTP API and the `/token` endpoint over ONE
//! database, and assert the join between them:
//!
//! - a workload authenticates with nothing but its ambient assertion against an anchor an
//!   operator registered over HTTP, and the token comes back under the mapped machine
//!   identity (criterion 1's granting path);
//! - disabling that anchor through the management API revokes live authentication, so the
//!   switch an operator reaches for under compromise is not inert;
//! - a mapping naming an unregistered anchor, or a principal that is not a registered
//!   machine identity, is refused at authoring time rather than silently matching nothing.
//!
//! The claim gate carries a `repository` claim, which is the GitHub Actions shape named in
//! the issue: the mapping fires for one repository and ref, not for every token the
//! issuer mints.

mod common;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{Harness, form, json};
use http_body_util::BodyExt;
use ironauth_admin::{AdminState, management_router};
use ironauth_config::{AdminConfig, Secret, SecretString};
use ironauth_jose::{EmissionOptions, JwkSet, SigningKey, sign_jws};
use tower::ServiceExt;

/// The grant type under test.
const JWT_BEARER_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
/// The bootstrap operator credential the management router is configured with.
const OPERATOR_TOKEN: &str = "test-bootstrap-operator-token";
/// The simulated platform issuer: GitHub Actions' OIDC provider.
const PLATFORM_ISSUER: &str = "https://token.actions.githubusercontent.com";
/// The workload's ambient subject, in GitHub Actions' `sub` shape.
const WORKLOAD_SUBJECT: &str = "repo:acme/widgets:ref:refs/heads/main";
/// The additional claim the mapping gates on, and the value it demands.
const GATE_CLAIM: &str = "repository";
const GATE_VALUE: &str = "acme/widgets";

/// The platform's signing key (a fixed seed: deterministic, and a secret only in the
/// technical sense).
fn platform_key() -> SigningKey {
    SigningKey::ed25519_from_seed(Some("gha".to_owned()), &[11_u8; 32]).expect("platform key")
}

/// The public JWK Set the platform publishes, exactly what an operator pins.
fn platform_jwks() -> String {
    JwkSet::from_signing_keys([&platform_key()])
        .expect("jwk set")
        .to_json()
        .expect("jwks json")
}

/// An ambient workload assertion, carrying the repository claim the mapping gates on.
fn workload_assertion(aud: &str, jti: &str, repository: &str) -> String {
    let claims = serde_json::json!({
        "iss": PLATFORM_ISSUER,
        "sub": WORKLOAD_SUBJECT,
        "aud": aud,
        "exp": 3600,
        "iat": 0,
        "jti": jti,
        GATE_CLAIM: repository,
    });
    let payload = serde_json::to_vec(&claims).expect("serialize claims");
    sign_jws(&platform_key(), &payload, &EmissionOptions::new()).expect("sign assertion")
}

/// The management plane over the SAME database the OIDC harness serves from.
///
/// The tenant is re-owned onto the bootstrap operator first. Every management read is
/// scoped to the operator that owns the tenant, and the OIDC harness seeds its scope under
/// a freshly minted one, so without this the surface answers a uniform not-found for a
/// tenant that plainly exists, and the test would measure the fixture rather than the
/// route.
async fn management_plane(h: &Harness) -> Router {
    let operator = ironauth_admin::bootstrap_operator_id().to_string();
    sqlx::query(
        "INSERT INTO operators /* query-audit-allow: owner test seed */ (id, display_name) \
         VALUES ($1, 'workload federation test') ON CONFLICT (id) DO NOTHING",
    )
    .bind(&operator)
    .execute(h.db().owner_pool())
    .await
    .expect("the bootstrap operator row exists");
    sqlx::query(
        "UPDATE tenants /* query-audit-allow: owner test seed */ SET operator_id = $1 \
         WHERE id = $2",
    )
    .bind(&operator)
    .bind(h.scope().tenant().to_string())
    .execute(h.db().owner_pool())
    .await
    .expect("the tenant is adopted by the bootstrap operator");

    let config = AdminConfig {
        bootstrap_operator_token: Some(Secret::Literal(SecretString::new(OPERATOR_TOKEN))),
        ..AdminConfig::default()
    };
    // The HARNESS's env, not a fresh `Env::system()`. The two planes must share one clock:
    // the harness runs a manual one, and a management write stamping its outbox row from the
    // system clock enqueues an event the data plane's claim never finds eligible. Measured,
    // not anticipated: the event assertions read an empty stream until this changed.
    let state = AdminState::new(h.db().control_store().clone(), h.env().clone(), &config)
        .expect("admin state builds");
    management_router(state)
}

/// `POST` a JSON body to the management plane as the bootstrap operator.
async fn manage_post(
    router: &Router,
    path: &str,
    idempotency_key: &str,
    body: &serde_json::Value,
) -> (StatusCode, String) {
    let request = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {OPERATOR_TOKEN}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header("Idempotency-Key", idempotency_key)
        .body(Body::from(body.to_string()))
        .expect("request builds");
    send(router, request).await
}

/// `PATCH` a JSON body to the management plane as the bootstrap operator.
async fn manage_patch(
    router: &Router,
    path: &str,
    body: &serde_json::Value,
) -> (StatusCode, String) {
    let request = Request::builder()
        .method("PATCH")
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {OPERATOR_TOKEN}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("request builds");
    send(router, request).await
}

/// `GET` from the management plane as the bootstrap operator.
async fn manage_get(router: &Router, path: &str) -> (StatusCode, String) {
    let request = Request::builder()
        .method("GET")
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {OPERATOR_TOKEN}"))
        .body(Body::empty())
        .expect("request builds");
    send(router, request).await
}

async fn send(router: &Router, request: Request<Body>) -> (StatusCode, String) {
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("the management router answers");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("read the body")
        .to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// The environment-scoped management prefix for the harness's own scope.
fn base(h: &Harness) -> String {
    format!(
        "/v1/tenants/{}/environments/{}",
        h.scope().tenant(),
        h.scope().environment()
    )
}

/// Mint the registered machine identity a mapping is allowed to name.
///
/// Service accounts have no create route: one is minted for a CLIENT, the way the
/// client-credentials grant does at first issuance, so this goes through the store exactly
/// as production does.
///
/// The identity is minted for a SECOND, freshly created client, never for the harness client
/// that presents the assertion. That is load bearing rather than tidy. `ensure` is stable
/// (minted once, read back afterwards), so an identity minted for the presenting client is a
/// pure function of the `client_id` on the token request, and the "the token is issued as the
/// mapped identity" assertion would then be satisfied by a grant that ignored the mapping
/// entirely and resolved the presenting client's own service account. Measured: with the
/// identity minted for the presenting client, replacing `Ok(mapping.principal)` in
/// `jwt_bearer.rs` with the presenting client's service account left the whole file green.
async fn machine_identity(h: &Harness) -> String {
    let (actor, corr) = h.seeding_actor();
    let other_client = h
        .store()
        .scoped(h.scope())
        .acting(actor, corr)
        .clients()
        .create(h.env(), "a federated workload")
        .await
        .expect("create the client the identity belongs to");
    assert_ne!(
        &other_client,
        h.client_id(),
        "the mapped identity must belong to a DIFFERENT client than the one presenting"
    );
    let (actor, corr) = h.seeding_actor();
    h.store()
        .scoped(h.scope())
        .acting(actor, corr)
        .service_accounts()
        .ensure(h.env(), &other_client)
        .await
        .expect("mint the machine identity")
        .to_string()
}

/// Register the platform anchor and a gated mapping onto `identity`, over HTTP.
async fn register_federation(router: &Router, h: &Harness, identity: &str) -> String {
    let (status, body) = manage_post(
        router,
        &format!("{}/external-issuers", base(h)),
        "register-platform",
        &serde_json::json!({
            "issuer": PLATFORM_ISSUER,
            "jwks": platform_jwks(),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "register the anchor: {body}");
    let anchor = json(&body)["id"]
        .as_str()
        .expect("the registration mints an id")
        .to_owned();

    let (status, body) = manage_post(
        router,
        &format!("{}/subject-mappings", base(h)),
        "map-workload",
        &serde_json::json!({
            "issuer": PLATFORM_ISSUER,
            "external_subject": WORKLOAD_SUBJECT,
            "match_claim": GATE_CLAIM,
            "match_value": GATE_VALUE,
            "principal": identity,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "map the subject: {body}");
    anchor
}

/// Present an ambient assertion at the live `/token` endpoint.
async fn authenticate(h: &Harness, jti: &str, repository: &str) -> (StatusCode, String) {
    let body = form(&[
        ("grant_type", JWT_BEARER_GRANT),
        (
            "assertion",
            &workload_assertion(h.issuer(), jti, repository),
        ),
        ("client_id", &h.client_id().to_string()),
    ]);
    let (status, _headers, body) = h.token(&body).await;
    (status, body)
}

/// Decode a compact JWS payload, for reading the issued token's claims.
fn jwt_payload(token: &str) -> serde_json::Value {
    use base64::Engine;
    let payload = token.split('.').nth(1).expect("jws has a payload");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("payload base64url");
    serde_json::from_slice(&bytes).expect("payload json")
}

/// Criterion 1's granting path: an operator registers a trust anchor over the management
/// API, and a workload holding nothing but its ambient platform assertion authenticates
/// against it as the mapped machine identity.
///
/// Zero stored secrets: the only credential in the exchange is the assertion the platform
/// issued, and the presenting client is public.
#[tokio::test]
async fn a_workload_authenticates_against_an_anchor_registered_over_the_management_api() {
    let h = Harness::start().await;
    let router = management_plane(&h).await;
    let identity = machine_identity(&h).await;
    register_federation(&router, &h, &identity).await;

    let (status, body) = authenticate(&h, "jti-granting-path", GATE_VALUE).await;
    assert_eq!(status, StatusCode::OK, "the workload authenticates: {body}");

    let response = json(&body);
    let access = response["access_token"].as_str().expect("an access token");
    let claims = jwt_payload(access);
    assert_eq!(
        claims["sub"],
        serde_json::json!(identity),
        "the token is issued AS the registered machine identity the mapping named, so the \
         registration decided who the workload becomes: {claims}"
    );
    // The mapped identity belongs to a DIFFERENT client than the presenting one (see
    // `machine_identity`), so this `sub` could not have come from resolving the presenter.
    let presenting_identity = h
        .store()
        .scoped(h.scope())
        .service_accounts()
        .principal_for(h.client_id())
        .await
        .expect("read the presenting client's own principal");
    assert_ne!(
        presenting_identity.map(|p| p.to_string()),
        Some(identity.clone()),
        "the fixture must not let the mapped identity coincide with the presenting client's \
         own service account, or this test cannot tell the mapping from the presenter"
    );
    assert_eq!(
        claims["client_id"],
        serde_json::json!(h.client_id().to_string()),
        "audienced to the presenting client: {claims}"
    );
    assert!(
        response.get("refresh_token").is_none(),
        "no refresh token is issued on the assertion grant: {body}"
    );

    // The gate the mapping was authored with is LIVE, not decorative: the same workload,
    // same anchor, same subject, one claim value different, authenticates nothing.
    let (status, body) = authenticate(&h, "jti-wrong-repository", "acme/other").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an assertion failing the authored claim gate was accepted: {body}"
    );
    assert_eq!(
        json(&body)["error"],
        serde_json::json!("invalid_grant"),
        "and it is refused as a grant failure: {body}"
    );
}

/// Disabling an anchor through the management API revokes live authentication.
///
/// This is the direction an operator reaches for when a platform is compromised, and it is
/// the half a surface can ship broken without anyone noticing: a toggle that writes a
/// column the grant does not consult reads as success and changes nothing. So the SAME
/// assertion shape is presented before and after, and the only difference between the two
/// exchanges is the PATCH.
#[tokio::test]
async fn disabling_an_anchor_over_the_management_api_revokes_live_authentication() {
    let h = Harness::start().await;
    let router = management_plane(&h).await;
    let identity = machine_identity(&h).await;
    let anchor = register_federation(&router, &h, &identity).await;

    let (status, body) = authenticate(&h, "jti-before-disable", GATE_VALUE).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the workload authenticates before the anchor is disabled: {body}"
    );

    let (status, body) = manage_patch(
        &router,
        &format!("{}/external-issuers/{anchor}", base(&h)),
        &serde_json::json!({ "enabled": false }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "disable the anchor: {body}");

    // A FRESH jti, so the refusal is the disabled anchor rather than the single-use replay
    // cache catching a resent assertion.
    let (status, body) = authenticate(&h, "jti-after-disable", GATE_VALUE).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a disabled anchor still authenticated a workload: {body}"
    );
    assert_eq!(
        json(&body)["error"],
        serde_json::json!("invalid_grant"),
        "and the refusal is opaque on the wire: {body}"
    );

    // And the switch goes BOTH ways. Every other assertion in the PR sends `enabled: false`,
    // so without this the handler could hardcode `false` and discard the caller's value: an
    // operator could disable an anchor during an incident and never get it back.
    let (status, body) = manage_patch(
        &router,
        &format!("{}/external-issuers/{anchor}", base(&h)),
        &serde_json::json!({ "enabled": true }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "re-enable the anchor: {body}"
    );
    let (status, body) = authenticate(&h, "jti-after-reenable", GATE_VALUE).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a re-enabled anchor did not authenticate the workload again: {body}"
    );

    // Back to disabled, so the listing assertion below reads the state this test is named for.
    let (status, body) = manage_patch(
        &router,
        &format!("{}/external-issuers/{anchor}", base(&h)),
        &serde_json::json!({ "enabled": false }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "disable again: {body}");

    // And the anchor reads back disabled, so the revocation is visible to the operator who
    // performed it rather than only inferable from a failing workload.
    let (status, body) = manage_get(&router, &format!("{}/external-issuers", base(&h))).await;
    assert_eq!(status, StatusCode::OK, "list the anchors: {body}");
    let listed = json(&body);
    let row = listed["issuers"]
        .as_array()
        .expect("an issuers array")
        .iter()
        .find(|entry| entry["id"] == serde_json::json!(anchor))
        .unwrap_or_else(|| panic!("the disabled anchor is still listed: {body}"));
    assert_eq!(
        row["enabled"],
        serde_json::json!(false),
        "the listing shows the anchor disabled: {body}"
    );
}

/// A mapping is refused unless both ends of it resolve.
///
/// Neither end is a foreign key: `issuer` is the issuer STRING an assertion carries rather
/// than the anchor's row id, and `principal` is free text the grant copies into the issued
/// token's `sub`. So the database accepts a typo in either, and the result is a rule that
/// matches nothing or one that mints tokens for a subject no reader can attribute. Both
/// are refused at authoring time, where the operator is still looking at the thing.
#[tokio::test]
async fn a_mapping_is_refused_unless_its_anchor_and_its_identity_both_resolve() {
    let h = Harness::start().await;
    let router = management_plane(&h).await;
    let identity = machine_identity(&h).await;
    let mappings = format!("{}/subject-mappings", base(&h));

    // No anchor registered yet, so the issuer names nothing.
    let (status, body) = manage_post(
        &router,
        &mappings,
        "map-before-anchor",
        &serde_json::json!({
            "issuer": PLATFORM_ISSUER,
            "external_subject": WORKLOAD_SUBJECT,
            "principal": identity,
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a mapping from an unregistered issuer was accepted: {body}"
    );
    assert!(
        body.contains(PLATFORM_ISSUER),
        "the refusal names the issuer that did not resolve: {body}"
    );

    register_federation(&router, &h, &identity).await;

    // A principal that is not a machine identifier at all.
    let (status, body) = manage_post(
        &router,
        &mappings,
        "map-free-text-principal",
        &serde_json::json!({
            "issuer": PLATFORM_ISSUER,
            "external_subject": "repo:acme/widgets:ref:refs/heads/release",
            "principal": "workload-alpha",
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a free-text principal was accepted as a mapped identity: {body}"
    );

    // And a WELL-FORMED identifier for an account that does not exist. This is the case a
    // shape check waves through, and the one an operator actually produces: a copied id
    // from another environment, or one whose account was deleted.
    let absent = ironauth_store::ServiceAccountId::generate(h.env(), &h.scope()).to_string();
    assert_ne!(absent, identity, "a DIFFERENT, unminted identifier");
    let (status, body) = manage_post(
        &router,
        &mappings,
        "map-absent-identity",
        &serde_json::json!({
            "issuer": PLATFORM_ISSUER,
            "external_subject": "repo:acme/widgets:ref:refs/tags/v1",
            "principal": absent,
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a well-formed identifier for an absent machine identity was accepted: {body}"
    );
    assert!(
        body.contains(&absent),
        "the refusal names the identity that does not exist: {body}"
    );

    // The positive control: the SAME request shape, with both ends resolving, is created.
    // Without it every assertion above is satisfied by a route that refuses everything.
    let (status, body) = manage_post(
        &router,
        &mappings,
        "map-both-resolve",
        &serde_json::json!({
            "issuer": PLATFORM_ISSUER,
            "external_subject": "repo:acme/widgets:ref:refs/tags/v2",
            "principal": identity,
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "a mapping whose anchor and identity both resolve is authored: {body}"
    );
}

/// A registration pins exactly one key source, and a mapping's claim gate is all or nothing.
///
/// Both are also database CHECK constraints, which is why they are easy to leave untested:
/// the row cannot be written either way, so the feature is never actually broken. What the
/// constraint cannot do is TELL the operator what is wrong. It surfaces as an opaque write
/// failure, and these two mistakes (pinning both key sources, naming a claim without the
/// value it must equal) are ordinary authoring slips with an obvious remedy. So the edge
/// refuses them with a message, and each refusal is paired with the request that succeeds.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn a_half_configured_anchor_or_claim_gate_is_refused_with_a_reason() {
    let h = Harness::start().await;
    let router = management_plane(&h).await;
    let identity = machine_identity(&h).await;
    let issuers = format!("{}/external-issuers", base(&h));
    let mappings = format!("{}/subject-mappings", base(&h));

    // NEITHER key source: nothing to verify a signature against.
    let (status, body) = manage_post(
        &router,
        &issuers,
        "anchor-keyless",
        &serde_json::json!({ "issuer": PLATFORM_ISSUER }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an anchor with no key source was registered: {body}"
    );
    assert!(
        body.contains("exactly one of jwks and jwks_uri is required"),
        "the keyless refusal must be the keyless one: with only a `jwks_uri` substring check, \
         swapping the two match arms is invisible because the mutual-exclusion message names \
         that field too: {body}"
    );

    // BOTH key sources: which one is authoritative is unstated.
    let (status, body) = manage_post(
        &router,
        &issuers,
        "anchor-dual-source",
        &serde_json::json!({
            "issuer": PLATFORM_ISSUER,
            "jwks": platform_jwks(),
            "jwks_uri": "https://token.actions.githubusercontent.com/.well-known/jwks",
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an anchor pinning both key sources was registered: {body}"
    );
    assert!(
        body.contains("mutually exclusive"),
        "and the dual-source caller is told which of the two rules it broke: {body}"
    );

    // An empty issuer, which would otherwise be a trust anchor matching an `iss` no
    // assertion carries.
    let (status, body) = manage_post(
        &router,
        &issuers,
        "anchor-empty-issuer",
        &serde_json::json!({ "issuer": "   ", "jwks": platform_jwks() }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an anchor with a blank issuer was registered: {body}"
    );

    // The positive control for all three: exactly one key source and a real issuer.
    let (status, body) = manage_post(
        &router,
        &issuers,
        "anchor-well-formed",
        &serde_json::json!({ "issuer": PLATFORM_ISSUER, "jwks": platform_jwks() }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "a well-formed anchor is registered: {body}"
    );

    // Each half of the claim gate without the other. Driven in BOTH directions, because a
    // check written as a one-sided `is_some()` passes one of them.
    for (label, gate) in [
        (
            "claim-without-value",
            serde_json::json!({ "match_claim": GATE_CLAIM }),
        ),
        (
            "value-without-claim",
            serde_json::json!({ "match_value": GATE_VALUE }),
        ),
    ] {
        let mut request = serde_json::json!({
            "issuer": PLATFORM_ISSUER,
            "external_subject": format!("repo:acme/widgets:ref:refs/heads/{label}"),
            "principal": identity,
        });
        for (key, value) in gate.as_object().expect("a gate object") {
            request[key] = value.clone();
        }
        let (status, body) = manage_post(&router, &mappings, label, &request).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a half-configured claim gate ({label}) was authored: {body}"
        );
        assert!(
            body.contains("match_claim") && body.contains("match_value"),
            "the refusal names both halves, so the operator learns the rule rather than the \
             field they happened to send ({label}): {body}"
        );
    }

    // The positive control: BOTH halves together are authored.
    let (status, body) = manage_post(
        &router,
        &mappings,
        "gate-both-halves",
        &serde_json::json!({
            "issuer": PLATFORM_ISSUER,
            "external_subject": WORKLOAD_SUBJECT,
            "match_claim": GATE_CLAIM,
            "match_value": GATE_VALUE,
            "principal": identity,
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "a mapping carrying both halves of the gate is authored: {body}"
    );
}

/// A trust anchor registered in one environment is unreachable from another.
///
/// The two environments share a TENANT and an operator, so nothing but the scope
/// separates the caller from the row. That is the sharp version of this probe: a
/// cross-tenant attempt is refused twice over (the operator does not own the tenant
/// either), which would hide a missing scope filter behind an ownership check.
///
/// Anchors are the highest-value row on this surface to get wrong. Reaching one across a
/// scope boundary means enabling an issuer in an environment the caller cannot otherwise
/// write, and every token that issuer can then mint follows from it.
#[tokio::test]
async fn a_trust_anchor_does_not_leak_across_the_environment_boundary() {
    let h = Harness::start().await;
    let router = management_plane(&h).await;
    let identity = machine_identity(&h).await;
    let anchor = register_federation(&router, &h, &identity).await;

    let neighbour = h.second_scope().await;
    let neighbour_base = format!(
        "/v1/tenants/{}/environments/{}",
        neighbour.tenant(),
        neighbour.environment()
    );

    // The neighbour registers its OWN anchor first. Asserting "the foreign anchor is absent"
    // against an empty listing is satisfied by a handler that answers a constant empty array,
    // so the listing has to be carrying something for its absence to mean anything.
    let (status, body) = manage_post(
        &router,
        &format!("{neighbour_base}/external-issuers"),
        "neighbour-anchor",
        &serde_json::json!({ "issuer": PLATFORM_ISSUER, "jwks": platform_jwks() }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "the neighbour registers its own anchor: {body}"
    );
    let neighbour_anchor = json(&body)["id"]
        .as_str()
        .expect("the registration mints an id")
        .to_owned();
    assert_ne!(neighbour_anchor, anchor, "two distinct rows");

    let (status, body) = manage_get(&router, &format!("{neighbour_base}/external-issuers")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the neighbouring environment's own listing resolves: {body}"
    );
    assert!(
        body.contains(&neighbour_anchor),
        "the neighbour's listing carries its own anchor, so it is reading the table: {body}"
    );
    assert!(
        !body.contains(&anchor),
        "an anchor registered in another environment appeared in this one's listing: {body}"
    );
    // Note the two rows share an ISSUER STRING. That is the sharp case: the unique constraint
    // is per (tenant, environment, issuer), so registering the same platform in both
    // environments is legitimate, and a listing that leaked across the boundary would show two.

    // And it cannot be addressed by id from the neighbour, which is the reach that would
    // matter: enabling or disabling an anchor in an environment the caller cannot write.
    let (status, body) = manage_patch(
        &router,
        &format!("{neighbour_base}/external-issuers/{anchor}"),
        &serde_json::json!({ "enabled": false }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a foreign anchor was addressable from a neighbouring environment: {body}"
    );

    // A machine identity is scoped the same way: a mapping in the neighbour cannot name one
    // minted in the first environment, which would otherwise mint tokens for a principal
    // that does not belong to the environment issuing them. The neighbour's anchor is already
    // registered above, so this refusal is about the PRINCIPAL and not a missing issuer.
    let (status, body) = manage_post(
        &router,
        &format!("{neighbour_base}/subject-mappings"),
        "neighbour-foreign-identity",
        &serde_json::json!({
            "issuer": PLATFORM_ISSUER,
            "external_subject": WORKLOAD_SUBJECT,
            "principal": identity,
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a mapping named a machine identity from another environment: {body}"
    );

    // The positive control: the SAME id, addressed under the scope it belongs to, resolves.
    // Without it every refusal above is satisfied by an anchor that was never written.
    let (status, body) = manage_patch(
        &router,
        &format!("{}/external-issuers/{anchor}", base(&h)),
        &serde_json::json!({ "enabled": false }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "the anchor resolves under its own environment: {body}"
    );
}

/// Every write on this surface announces itself on the event stream.
///
/// `scripts/producer-coverage.py` requires a management write to call a `*_with_event` store
/// method, but it reads the SOURCE: a handler passing `None` for the event satisfies the
/// scan and emits nothing. So this drives the four writes and reads the outbox, which is
/// where a receiver would actually learn about them.
///
/// Trust configuration is the case where silence is worst. An integrator reconciling "whose
/// signature can mint a token in this environment" against its own records has the event
/// stream and nothing else; an anchor registered or revoked outside it is invisible until
/// something breaks.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn every_trust_configuration_write_announces_itself() {
    let h = Harness::start().await;
    let router = management_plane(&h).await;
    let identity = machine_identity(&h).await;
    let anchor = register_federation(&router, &h, &identity).await;

    // Both toggles are driven, so the REVOCATION direction is measured and not only the two
    // creates the fixture already made.
    let (status, body) = manage_patch(
        &router,
        &format!("{}/external-issuers/{anchor}", base(&h)),
        &serde_json::json!({ "enabled": false }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "disable the anchor: {body}");

    let (status, body) = manage_get(&router, &format!("{}/subject-mappings", base(&h))).await;
    assert_eq!(status, StatusCode::OK, "list the mappings: {body}");
    let mapping = json(&body)["mappings"]
        .as_array()
        .expect("a mappings array")
        .first()
        .expect("the mapping the fixture authored")["id"]
        .as_str()
        .expect("a mapping id")
        .to_owned();
    let (status, body) = manage_patch(
        &router,
        &format!("{}/subject-mappings/{mapping}", base(&h)),
        &serde_json::json!({ "enabled": false }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "disable the mapping: {body}"
    );

    // The mapping toggle in the OTHER direction too. Round 1 fixed this for the anchor route
    // and left the mapping's untouched, so `request.enabled` there could still have been
    // replaced by a hardcoded `false` with the whole tree green.
    let (status, body) = manage_patch(
        &router,
        &format!("{}/subject-mappings/{mapping}", base(&h)),
        &serde_json::json!({ "enabled": true }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "re-enable the mapping: {body}"
    );
    let (status, body) = manage_get(&router, &format!("{}/subject-mappings", base(&h))).await;
    assert_eq!(status, StatusCode::OK, "read the mappings back: {body}");
    assert_eq!(
        json(&body)["mappings"]
            .as_array()
            .expect("array")
            .iter()
            .find(|m| m["id"] == serde_json::json!(mapping))
            .expect("the mapping is listed")["enabled"],
        serde_json::json!(true),
        "the mapping reads back enabled, so the PATCH wrote the caller's value: {body}"
    );

    // And BOTH deletes, so their events are driven here. Nothing else in the suite reads the
    // outbox, so without this the two delete handlers could pass `None` for their event and
    // announce nothing: `producer-coverage.py` is satisfied by the literal string
    // `delete_with_event(` matching its `*_event(` shape, which is the exact hole this test's
    // own doc says it exists to close.
    let delete = |path: String| {
        let router = router.clone();
        async move {
            let request = axum::http::Request::builder()
                .method("DELETE")
                .uri(path)
                .header(header::AUTHORIZATION, format!("Bearer {OPERATOR_TOKEN}"))
                .body(Body::empty())
                .expect("request builds");
            send(&router, request).await
        }
    };
    let (status, body) = delete(format!("{}/subject-mappings/{mapping}", base(&h))).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "delete the mapping: {body}");
    let (status, body) = delete(format!("{}/external-issuers/{anchor}", base(&h))).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "delete the anchor: {body}");

    // Read the queue the fan-out consumes, which is where an event has to BE for any
    // receiver to see it. Claiming rather than selecting is what a consumer does, and each
    // message is COMPLETED before the next claim: two events about one subject share an
    // ordering key, so the second stays blocked behind the first until the first is done.
    // Draining without completing reads only the head of each group, which is how the first
    // version of this test concluded the two toggles announced nothing.
    let mut announced: Vec<serde_json::Value> = Vec::new();
    // The ordering KEY travels beside the payload. Asserting only that the registration comes
    // before the disable proves nothing on its own: `claim` returns each batch ordered by
    // `sequence`, so the two stay in insertion order whether or not they share a group. What
    // makes the delivery guarantee real is that they share an ordering key, which is what the
    // head-of-line block in `claim` acts on.
    let mut keys: Vec<(String, String)> = Vec::new();
    loop {
        let claimed = h
            .store()
            .scoped(h.scope())
            .outbox()
            .claim(
                h.env(),
                ironauth_store::WEBHOOK_EVENT_CONSUMER,
                std::time::Duration::from_secs(30),
                100,
            )
            .await
            .expect("claim the enqueued events");
        if claimed.is_empty() {
            break;
        }
        for message in claimed {
            if let Some(kind) = message.payload["type"].as_str() {
                keys.push((kind.to_owned(), message.ordering_key.clone()));
            }
            announced.push(message.payload.clone());
            h.store()
                .scoped(h.scope())
                .outbox()
                .complete(h.env(), &message)
                .await
                .expect("complete a drained event");
        }
    }

    // Delivered in the order they happened. A receiver that saw the disable before the
    // registration would reconstruct an anchor that is live, which is the opposite of the
    // truth and the reason these two share an ordering key at all.
    let order: Vec<&str> = announced
        .iter()
        .filter_map(|event| event["type"].as_str())
        .collect();
    let registered = order
        .iter()
        .position(|t| *t == "external_issuer.registered")
        .expect("the registration is on the stream");
    let disabled = order
        .iter()
        .position(|t| *t == "external_issuer.enabled_changed")
        .expect("the disable is on the stream");
    assert!(
        registered < disabled,
        "an anchor's disable was delivered before its registration: {order:?}"
    );
    let key_of = |kind: &str| {
        keys.iter().find(|(k, _)| k == kind).map_or_else(
            || panic!("{kind} is NOT on the stream: {keys:?}"),
            |(_, key)| key.clone(),
        )
    };
    assert_eq!(
        key_of("external_issuer.registered"),
        key_of("external_issuer.enabled_changed"),
        "the two events about one anchor must share an ordering key, or nothing holds them in \
         order and the assertion above passes by accident: {keys:?}"
    );
    assert_eq!(
        key_of("external_issuer.registered"),
        PLATFORM_ISSUER,
        "an anchor's events are keyed on its NATURAL key, the issuer string, so a repoint's \
         delete and re-register stay ordered even though they are different rows: {keys:?}"
    );
    assert_eq!(
        key_of("subject_mapping.created"),
        key_of("subject_mapping.enabled_changed"),
        "the two events about one mapping must share an ordering key: {keys:?}"
    );
    // Pinned to the VALUE, not merely to each other. Self-consistency alone is satisfied by
    // any shared constant, which would put every mapping in the environment into one ordering
    // group and quietly serialize unrelated deliveries.
    assert_eq!(
        key_of("subject_mapping.created"),
        format!("{PLATFORM_ISSUER}\n{WORKLOAD_SUBJECT}"),
        "a mapping's events are keyed on its natural key, the (issuer, subject) pair: {keys:?}"
    );
    // The two DELETES, which is the pair the natural key exists for. A repoint is
    // delete-then-register, so if the delete falls back to the row id it lands in a different
    // ordering group from the registration that replaces it and the two can be delivered in
    // either order. Every other assertion here passed while these two were unmeasured.
    assert_eq!(
        key_of("external_issuer.deleted"),
        PLATFORM_ISSUER,
        "an anchor's DELETE shares the ordering key of the registration that replaces it, or a \
         repoint can be delivered as a revocation: {keys:?}"
    );
    assert_eq!(
        key_of("subject_mapping.deleted"),
        format!("{PLATFORM_ISSUER}\n{WORKLOAD_SUBJECT}"),
        "a mapping's DELETE shares the ordering key of the rule that replaces it: {keys:?}"
    );

    for (event_type, expected) in [
        (
            "external_issuer.registered",
            serde_json::json!({ "issuer": PLATFORM_ISSUER, "enabled": true }),
        ),
        (
            "external_issuer.enabled_changed",
            // The issuer travels WITH the toggle, not only as its ordering key: it is what a
            // receiver reconciles trust by, and this is the one event on the resource from
            // which it could not otherwise be recovered.
            serde_json::json!({ "issuer": PLATFORM_ISSUER, "enabled": false }),
        ),
        (
            "subject_mapping.created",
            serde_json::json!({
                "issuer": PLATFORM_ISSUER,
                "external_subject": WORKLOAD_SUBJECT,
                "principal": identity,
            }),
        ),
        (
            "subject_mapping.enabled_changed",
            serde_json::json!({
                "issuer": PLATFORM_ISSUER,
                "external_subject": WORKLOAD_SUBJECT,
                "enabled": false,
            }),
        ),
        (
            "subject_mapping.deleted",
            serde_json::json!({
                "issuer": PLATFORM_ISSUER,
                "external_subject": WORKLOAD_SUBJECT,
            }),
        ),
        (
            "external_issuer.deleted",
            serde_json::json!({ "issuer": PLATFORM_ISSUER }),
        ),
    ] {
        let found = announced
            .iter()
            .find(|event| event["type"] == serde_json::json!(event_type))
            .unwrap_or_else(|| {
                let types: Vec<&str> = announced
                    .iter()
                    .filter_map(|e| e["type"].as_str())
                    .collect();
                panic!("nothing announced {event_type}; the stream carried {types:?}")
            });
        // The PAYLOAD, not only the type. An event whose type is right and whose payload is
        // empty tells a receiver that something changed and not what, which for trust
        // configuration is the same as telling it nothing.
        for (key, value) in expected.as_object().expect("an object") {
            assert_eq!(
                &found["payload"][key], value,
                "{event_type} carries the wrong {key}: {found}"
            );
        }
        // The RIGHT row, not merely a non-empty string. Both the catalog schema and an
        // is-non-empty check are satisfied by four near-identical handlers that paste the
        // wrong id, which is the realistic slip here.
        let named = found["payload"]
            .get("issuer_id")
            .or_else(|| found["payload"].get("mapping_id"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("{event_type} names no row at all: {found}"));
        let expected_row = if found["payload"].get("issuer_id").is_some() {
            &anchor
        } else {
            &mapping
        };
        assert_eq!(
            named, expected_row,
            "{event_type} names the wrong row: {found}"
        );
    }
}

/// An anchor whose key source or algorithm pin could never verify anything is refused.
///
/// Each of these registers cleanly today, lists as enabled, and authenticates nothing,
/// because the grant fails CLOSED on all three: a key set with no usable key resolves to no
/// keys, an algorithm name the JOSE core does not implement intersects the supported set to
/// empty, and the SSRF-hardened fetcher resolves nothing over a non-https scheme.
///
/// That is the worst shape a configuration mistake can take here. An operator looking at the
/// listing sees an enabled trust anchor and concludes the problem is at the other end, so the
/// misconfiguration survives exactly as long as it takes someone to read the JWKS by hand.
#[tokio::test]
async fn an_anchor_that_could_never_verify_anything_is_refused_at_registration() {
    let h = Harness::start().await;
    let router = management_plane(&h).await;
    let issuers = format!("{}/external-issuers", base(&h));

    for (label, body) in [
        (
            "jwks that is not JSON at all",
            serde_json::json!({ "issuer": PLATFORM_ISSUER, "jwks": "not json" }),
        ),
        (
            "jwks that is valid JSON carrying no key",
            serde_json::json!({ "issuer": PLATFORM_ISSUER, "jwks": r#"{"keys":[]}"# }),
        ),
        (
            // Valid JWK Set shape, and every key in it unusable. This is the case a JSON
            // parse check waves through, which is why the check runs the verifier's reader.
            "jwks whose only key uses an unsupported type",
            serde_json::json!({
                "issuer": PLATFORM_ISSUER,
                "jwks": r#"{"keys":[{"kty":"XX","crv":"nope","x":"AA","kid":"k"}]}"#,
            }),
        ),
        (
            "jwks_uri over http",
            serde_json::json!({
                "issuer": PLATFORM_ISSUER,
                "jwks_uri": "http://token.actions.githubusercontent.com/keys",
            }),
        ),
        (
            "an algorithm the JOSE core does not implement",
            serde_json::json!({
                "issuer": PLATFORM_ISSUER,
                "jwks": platform_jwks(),
                "signing_alg_allow": "ES512",
            }),
        ),
        (
            // One good name and one bad one. The bad name alone would narrow the policy to
            // something the operator did not write, so the whole list is refused rather than
            // the unrecognised entry silently dropped.
            "one unrecognised algorithm beside a supported one",
            serde_json::json!({
                "issuer": PLATFORM_ISSUER,
                "jwks": platform_jwks(),
                "signing_alg_allow": "EdDSA HS256-but-typoed",
            }),
        ),
    ] {
        let (status, answer) = manage_post(&router, &issuers, label, &body).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "an anchor that could never verify anything was registered ({label}): {answer}"
        );
    }

    // The positive controls, one per rule, so none of the refusals above is satisfied by a
    // route that refuses every registration.
    for (label, body) in [
        (
            "inline-jwks",
            serde_json::json!({ "issuer": PLATFORM_ISSUER, "jwks": platform_jwks() }),
        ),
        (
            "https-jwks-uri",
            serde_json::json!({
                "issuer": "https://kubernetes.default.svc",
                "jwks_uri": "https://kubernetes.default.svc/openid/v1/jwks",
            }),
        ),
        (
            "a supported algorithm pin",
            serde_json::json!({
                "issuer": "https://spire.example/workload",
                "jwks": platform_jwks(),
                "signing_alg_allow": "EdDSA",
            }),
        ),
    ] {
        let (status, answer) = manage_post(&router, &issuers, label, &body).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "a well-formed anchor was refused ({label}): {answer}"
        );
    }
}

/// A mis-registered anchor can be corrected, which disable alone does not allow.
///
/// This is the case the first draft of this surface could not serve, and the reason it
/// matters is not a typo. Both tables carry a UNIQUE constraint on their natural key with no
/// `enabled` predicate, so a parked row keeps occupying it: with disable alone, an issuer that
/// ROTATES the keys behind a pinned inline `jwks` can never be repointed. The `iss` string is
/// dictated by the external platform, so there is no second key to register under, and every
/// workload behind that anchor stays unable to authenticate forever.
///
/// So the sequence here is the real operator story end to end: register, authenticate, the
/// platform rotates, authentication breaks, correct it, authentication works again.
#[tokio::test]
async fn a_rotated_issuer_can_be_repointed_by_deleting_and_re_registering() {
    let h = Harness::start().await;
    let router = management_plane(&h).await;
    let identity = machine_identity(&h).await;
    let issuers = format!("{}/external-issuers", base(&h));

    // Registered against a key that is NOT the platform's, standing in for the key set the
    // platform has since rotated away from.
    let stale = JwkSet::from_signing_keys([&SigningKey::ed25519_from_seed(
        Some("stale".to_owned()),
        &[3_u8; 32],
    )
    .expect("stale key")])
    .expect("jwk set")
    .to_json()
    .expect("jwks json");
    let (status, body) = manage_post(
        &router,
        &issuers,
        "rotate-register",
        &serde_json::json!({ "issuer": PLATFORM_ISSUER, "jwks": stale }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "register the anchor: {body}");
    let anchor = json(&body)["id"].as_str().expect("an id").to_owned();

    let (status, body) = manage_post(
        &router,
        &format!("{}/subject-mappings", base(&h)),
        "rotate-map",
        &serde_json::json!({
            "issuer": PLATFORM_ISSUER,
            "external_subject": WORKLOAD_SUBJECT,
            "match_claim": GATE_CLAIM,
            "match_value": GATE_VALUE,
            "principal": identity,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "map the subject: {body}");

    // The platform's CURRENT key does not verify against the stale set: this is what a rotation
    // looks like from the workload's side.
    let (status, body) = authenticate(&h, "jti-stale-key", GATE_VALUE).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an assertion signed by the rotated-in key verified against the stale set: {body}"
    );

    // Disabling does NOT free the key, which is the whole finding.
    let (status, body) = manage_patch(
        &router,
        &format!("{issuers}/{anchor}"),
        &serde_json::json!({ "enabled": false }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "park the anchor: {body}");
    let (status, body) = manage_post(
        &router,
        &issuers,
        "rotate-reregister-parked",
        &serde_json::json!({ "issuer": PLATFORM_ISSUER, "jwks": platform_jwks() }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a DISABLED row still occupies the unique key, so parking cannot be the remedy; if \
         this ever answers 201 the delete below has stopped being necessary and this test \
         should say so: {body}"
    );

    // Deleting does.
    let (status, body) = manage_patch(
        &router,
        &format!("{issuers}/{anchor}"),
        &serde_json::json!({ "enabled": true }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "un-park it first: {body}");
    let request = axum::http::Request::builder()
        .method("DELETE")
        .uri(format!("{issuers}/{anchor}"))
        .header(header::AUTHORIZATION, format!("Bearer {OPERATOR_TOKEN}"))
        .body(Body::empty())
        .expect("request builds");
    let (status, body) = send(&router, request).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "delete the anchor: {body}");

    let (status, body) = manage_post(
        &router,
        &issuers,
        "rotate-reregister",
        &serde_json::json!({ "issuer": PLATFORM_ISSUER, "jwks": platform_jwks() }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "the same issuer could not be registered again after the delete: {body}"
    );

    // And the workload authenticates again, against the rotated-in key. The MAPPING was never
    // touched: it names the issuer STRING, not the deleted row, so it survives the repoint,
    // which is the reason these are sibling resources rather than nested ones.
    let (status, body) = authenticate(&h, "jti-after-repoint", GATE_VALUE).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the workload did not authenticate after the anchor was repointed: {body}"
    );
}

/// Deleting a mapping frees its natural key too, and is refused across a scope boundary.
#[tokio::test]
async fn a_mapping_can_be_replaced_and_a_foreign_one_cannot_be_deleted() {
    let h = Harness::start().await;
    let router = management_plane(&h).await;
    let identity = machine_identity(&h).await;
    let mappings = format!("{}/subject-mappings", base(&h));
    register_federation(&router, &h, &identity).await;

    // The seeded mapping already occupies (issuer, external_subject).
    let (status, body) = manage_get(&router, &mappings).await;
    assert_eq!(status, StatusCode::OK, "list the mappings: {body}");
    let mapping = json(&body)["mappings"].as_array().expect("array")[0]["id"]
        .as_str()
        .expect("an id")
        .to_owned();

    let replacement = serde_json::json!({
        "issuer": PLATFORM_ISSUER,
        "external_subject": WORKLOAD_SUBJECT,
        "principal": identity,
    });
    let (status, body) = manage_post(&router, &mappings, "replace-blocked", &replacement).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "the natural key is occupied until the row is deleted: {body}"
    );

    // A foreign scope cannot delete it: the id resolves only under the scope it belongs to.
    let neighbour = h.second_scope().await;
    let foreign = format!(
        "/v1/tenants/{}/environments/{}/subject-mappings/{mapping}",
        neighbour.tenant(),
        neighbour.environment()
    );
    let request = axum::http::Request::builder()
        .method("DELETE")
        .uri(&foreign)
        .header(header::AUTHORIZATION, format!("Bearer {OPERATOR_TOKEN}"))
        .body(Body::empty())
        .expect("request builds");
    let (status, body) = send(&router, request).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a mapping was deletable from a neighbouring environment: {body}"
    );

    // Under its own scope it deletes, and the key is free again.
    let request = axum::http::Request::builder()
        .method("DELETE")
        .uri(format!("{mappings}/{mapping}"))
        .header(header::AUTHORIZATION, format!("Bearer {OPERATOR_TOKEN}"))
        .body(Body::empty())
        .expect("request builds");
    let (status, body) = send(&router, request).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "delete the mapping: {body}");

    let (status, body) = manage_post(&router, &mappings, "replace-allowed", &replacement).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "the freed key could not be re-authored: {body}"
    );

    // The delete is idempotent-safe: a second one is the uniform not-found, not a 500.
    let request = axum::http::Request::builder()
        .method("DELETE")
        .uri(format!("{mappings}/{mapping}"))
        .header(header::AUTHORIZATION, format!("Bearer {OPERATOR_TOKEN}"))
        .body(Body::empty())
        .expect("request builds");
    let (status, body) = send(&router, request).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "deleting an already-deleted mapping must answer the uniform not-found: {body}"
    );
}

/// The registration refuses the mistakes a shape check would wave through.
///
/// Four separate hazards, each of which produces an anchor or a mapping that is written,
/// listed, shown as enabled, and inert:
///
/// - this deployment registered as a foreign issuer of ITSELF. The JOSE core reads an external
///   assertion under a policy that by construction does not enforce `typ`, and both that policy
///   and the grant document the hazard while relying on the same mitigation: that no operator
///   could register such an anchor. This surface is what removed that mitigation.
/// - an issuer or subject carrying surrounding whitespace, which matches exactly nothing
///   because the grant compares `iss` and `sub` byte for byte.
/// - an empty `external_subject`, which is worse than useless: the `subject_mapping.created`
///   schema requires a non-empty string, so the row would commit and its event would fail
///   catalog validation at fan-out, leaving a live mapping no receiver was ever told about.
/// - an `audience_allow` that lists nothing, which narrows the accepted audiences to the empty
///   set exactly as an unrecognised algorithm name would.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn the_surface_refuses_configurations_that_would_be_written_and_inert() {
    let h = Harness::start().await;
    let router = management_plane(&h).await;
    let identity = machine_identity(&h).await;
    let issuers = format!("{}/external-issuers", base(&h));
    let mappings = format!("{}/subject-mappings", base(&h));

    // This environment's own issuer, read from the same registry the data plane serves it from
    // rather than reconstructed here, so the test cannot pass by comparing against a string the
    // deployment does not actually use.
    let own_issuer = h.issuer().to_owned();
    let (status, body) = manage_post(
        &router,
        &issuers,
        "self-anchor",
        &serde_json::json!({ "issuer": own_issuer, "jwks": platform_jwks() }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the deployment was registered as a foreign trust anchor of itself: {body}"
    );

    // An empty audience allowlist.
    let (status, body) = manage_post(
        &router,
        &issuers,
        "empty-audience",
        &serde_json::json!({
            "issuer": PLATFORM_ISSUER,
            "jwks": platform_jwks(),
            "audience_allow": "   ",
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an anchor accepting no audience at all was registered: {body}"
    );
    // And an empty algorithm allowlist, the sibling rule, which had no test.
    let (status, body) = manage_post(
        &router,
        &issuers,
        "empty-alg",
        &serde_json::json!({
            "issuer": PLATFORM_ISSUER,
            "jwks": platform_jwks(),
            "signing_alg_allow": "   ",
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an anchor permitting no algorithm at all was registered: {body}"
    );

    // A padded issuer is REFUSED rather than silently trimmed. Trimming looks kinder and is
    // an authorization substitution: `iss` and `sub` are compared byte for byte by the grant,
    // and `str::trim` strips the whole Unicode `White_Space` set, so a subject ending in a
    // non-breaking space would be rewritten into the plain ref, which is a different and
    // usually far more broadly writable one. An earlier draft of this change trimmed.
    let padded = format!("  {PLATFORM_ISSUER}  ");
    let (status, body) = manage_post(
        &router,
        &issuers,
        "padded-issuer",
        &serde_json::json!({ "issuer": padded, "jwks": platform_jwks() }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an issuer with surrounding whitespace was accepted: {body}"
    );
    let (status, body) = manage_post(
        &router,
        &issuers,
        "clean-issuer",
        &serde_json::json!({ "issuer": PLATFORM_ISSUER, "jwks": platform_jwks() }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "register the clean issuer: {body}"
    );
    // The same for a padded external subject, which is the one that actually matters.
    let (status, body) = manage_post(
        &router,
        &mappings,
        "padded-subject",
        &serde_json::json!({
            "issuer": PLATFORM_ISSUER,
            "external_subject": format!("{WORKLOAD_SUBJECT}\u{00A0}"),
            "principal": identity,
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a subject ending in a non-breaking space was accepted, and trimming it would have \
         silently authorized the plain ref instead: {body}"
    );

    // An empty external subject, refused rather than committed with an undeliverable event.
    let (status, body) = manage_post(
        &router,
        &mappings,
        "empty-subject",
        &serde_json::json!({
            "issuer": PLATFORM_ISSUER,
            "external_subject": "   ",
            "principal": identity,
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a mapping with no external subject was authored: {body}"
    );

    // A value too long to index. Unbounded, this is not a 400 but an opaque 500: the string is
    // part of a btree UNIQUE key, Postgres refuses an oversized index row with SQLSTATE 54000,
    // and that is neither a unique nor a check violation, so the store cannot classify it.
    let (status, body) = manage_post(
        &router,
        &issuers,
        "oversized-issuer",
        &serde_json::json!({
            "issuer": format!("https://x.example/{}", "a".repeat(4096)),
            "jwks": platform_jwks(),
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an issuer too long to index was accepted, and would surface as a 500: {body}"
    );

    // An oversized external SUBJECT, which is the half that actually needs the cap: an over-long
    // mapping issuer is caught anyway by the anchor lookup, while nothing else in the stack
    // bounds the subject, and it is the field that decides whether the mappings' four-column
    // unique key and the outbox ordering key overflow.
    //
    // The cap is on RAW BYTE LENGTH and runs in Rust before any SQL, so the content of the value
    // is irrelevant to this assertion and no attempt is made to defeat Postgres compression. An
    // earlier version of this comment claimed the opposite and named its fixture `incompressible`
    // while generating a 26-byte cycle, which is about as compressible as text gets. What the
    // cap buys is that the refusal is a 400 naming the field, rather than the index-row error the
    // store cannot classify; proving the underlying Postgres behaviour would take a store-level
    // test with a genuinely incompressible value, which this is not.
    let oversized = "b".repeat(2000);
    let (status, body) = manage_post(
        &router,
        &mappings,
        "oversized-subject",
        &serde_json::json!({
            "issuer": PLATFORM_ISSUER,
            "external_subject": oversized,
            "principal": identity,
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an external subject over the byte cap was accepted: {body}"
    );

    // A claim gate half carrying surrounding whitespace, which the grant compares byte for
    // byte exactly as it compares the issuer and the subject.
    let (status, body) = manage_post(
        &router,
        &mappings,
        "padded-claim",
        &serde_json::json!({
            "issuer": PLATFORM_ISSUER,
            "external_subject": "repo:acme/widgets:ref:refs/heads/padded-claim",
            "match_claim": format!(" {GATE_CLAIM} "),
            "match_value": GATE_VALUE,
            "principal": identity,
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a claim gate with a padded claim name was authored: {body}"
    );

    // Half a claim gate that is present but EMPTY. The both-or-neither rule and the database
    // CHECK are both satisfied by this, and the grant would then look for a claim named "",
    // which no assertion carries.
    for (label, gate) in [
        (
            "an empty claim name",
            serde_json::json!({ "match_claim": "", "match_value": GATE_VALUE }),
        ),
        (
            "an empty claim value",
            serde_json::json!({ "match_claim": GATE_CLAIM, "match_value": "" }),
        ),
    ] {
        let mut request = serde_json::json!({
            "issuer": PLATFORM_ISSUER,
            "external_subject": format!("repo:acme/widgets:ref:refs/heads/{label}"),
            "principal": identity,
        });
        for (key, value) in gate.as_object().expect("a gate object") {
            request[key] = value.clone();
        }
        let (status, body) = manage_post(&router, &mappings, label, &request).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a claim gate with {label} was authored, and would fire for nothing: {body}"
        );
    }

    // A LONE empty half, which is what pins the check ORDER. A client library that serialises an
    // unset optional string as "" sends this meaning "no gate at all". The pairing rule is the
    // message that names that mistake; the emptiness messages describe what a live gate would do,
    // and no gate would be authored here at all. Before the reorder each emptiness check fired
    // first and told the caller about a consequence that could not occur.
    for (label, gate) in [
        (
            "a lone empty value",
            serde_json::json!({ "match_value": "" }),
        ),
        (
            "a lone empty claim",
            serde_json::json!({ "match_claim": "" }),
        ),
    ] {
        let mut request = serde_json::json!({
            "issuer": PLATFORM_ISSUER,
            "external_subject": format!("repo:acme/widgets:ref:refs/heads/{label}"),
            "principal": identity,
        });
        for (key, value) in gate.as_object().expect("a gate object") {
            request[key] = value.clone();
        }
        let (status, body) = manage_post(&router, &mappings, label, &request).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a half-set claim gate ({label}) was authored: {body}"
        );
        assert!(
            body.contains("supplied together"),
            "a LONE half must be told the halves come as a pair, not what a live gate would do: \
             it authors no gate at all ({label}): {body}"
        );
    }

    // The positive control for all of the above: a well-formed mapping against the anchor the
    // "clean-issuer" POST created, so none of the refusals is satisfied by a dead route. NOT
    // the padded registration, which was refused and created nothing.
    let (status, body) = manage_post(
        &router,
        &mappings,
        "well-formed",
        &serde_json::json!({
            "issuer": PLATFORM_ISSUER,
            "external_subject": WORKLOAD_SUBJECT,
            "principal": identity,
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "a well-formed mapping was refused: {body}"
    );
}

/// The validation agrees with the machinery it defers to, in both directions.
///
/// Every case here is a behaviour the round-1 rewrite CHANGED, and none of them had a test:
/// the docstring asserted them and nothing measured them, which is how the version before it
/// drifted from the verifier in the first place. A false POSITIVE here is as bad as a false
/// negative, because it refuses an operator a registration that would have worked.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn the_registration_checks_agree_with_the_verifier_and_the_fetcher() {
    let h = Harness::start().await;
    let router = management_plane(&h).await;
    let issuers = format!("{}/external-issuers", base(&h));

    // ACCEPTED, because the verifier accepts them. `from_jose_name` maps `Ed25519` onto
    // `EdDSA` (draft-ietf-jose-fully-specified-algorithms), and the earlier draft compared
    // against the discovery list, which carries only the canonical spelling and so refused a
    // registration the grant honours. `http::Uri` lowercases a known scheme, and RFC 3986
    // makes schemes case insensitive, so the fetcher takes `HTTPS://`.
    for (label, body) in [
        (
            "the fully-specified EdDSA spelling",
            serde_json::json!({
                "issuer": "https://spire.example/a",
                "jwks": platform_jwks(),
                "signing_alg_allow": "Ed25519",
            }),
        ),
        (
            "an uppercase scheme",
            serde_json::json!({
                "issuer": "https://spire.example/b",
                "jwks_uri": "HTTPS://keys.example/jwks",
            }),
        ),
    ] {
        let (status, answer) = manage_post(&router, &issuers, label, &body).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "a registration the verifier would honour was refused ({label}): {answer}"
        );
    }

    // REFUSED, because the fetcher can never resolve them. Each is accepted by a
    // `starts_with(\"https://\")` prefix test, which is what the earlier draft used.
    for (label, uri) in [
        ("a scheme and nothing else", "https://"),
        ("userinfo in the authority", "https://svc@keys.example/jwks"),
        ("port zero", "https://keys.example:0/jwks"),
        // An IP LITERAL the SSRF policy always blocks. A hostname that RESOLVES to one of
        // these cannot be checked at authoring time and is deliberately left to the fetcher,
        // but a literal needs no resolution to judge.
        ("loopback", "https://127.0.0.1/jwks"),
        ("IPv6 loopback", "https://[::1]/jwks"),
        ("the cloud metadata address", "https://169.254.169.254/jwks"),
    ] {
        let (status, answer) = manage_post(
            &router,
            &issuers,
            label,
            &serde_json::json!({ "issuer": format!("https://x.example/{label}"), "jwks_uri": uri }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a jwks_uri the fetcher can never resolve was accepted ({label}): {answer}"
        );
    }

    // The self-issuer refusal covers the whole DEPLOYMENT, not just the scope being written.
    // The neighbour's issuer is served by this same deployment, its key set is public, and
    // the default audience policy accepts the deployment-wide token endpoint URL, so
    // registering it here would reach the same `typ`-unread path as registering our own.
    let neighbour = h.second_scope().await;
    // Derived from the harness's OWN issuer rather than a hand-written base, so this really is
    // a string this deployment serves. An earlier draft hardcoded a different host, which made
    // the sentence above false while the assertion still happened to pass.
    let own = h.issuer();
    let base = own
        .rsplit_once("/t/")
        .map(|(prefix, _)| prefix)
        .expect("the harness issuer carries the scope suffix");
    let neighbours_issuer = format!(
        "{base}/t/{}/e/{}",
        neighbour.tenant(),
        neighbour.environment()
    );
    assert_ne!(
        neighbours_issuer, own,
        "a DIFFERENT scope of the same deployment"
    );
    let (status, body) = manage_post(
        &router,
        &issuers,
        "neighbour-self-issuer",
        &serde_json::json!({ "issuer": neighbours_issuer, "jwks": platform_jwks() }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "another environment of this same deployment was registered as a foreign trust \
         anchor: {body}"
    );

    // Third-party issuers that resemble a scope are still ACCEPTED, and each of these varies
    // exactly ONE of the guard's four conjuncts away from the self-issuer shape. Without that,
    // deleting any single conjunct leaves the whole suite green: the refusals stay refused
    // because the other three still hold, and a lookalike failing on two conjuncts stays
    // accepted whichever one is removed.
    let (real_tenant, real_environment) = (
        h.scope().tenant().to_string(),
        h.scope().environment().to_string(),
    );
    for (label, path) in [
        (
            "a non-scope tenant segment",
            format!("/t/acme/e/{real_environment}"),
        ),
        (
            "a non-scope environment segment",
            format!("/t/{real_tenant}/e/prod"),
        ),
        (
            "a different first marker",
            format!("/x/{real_tenant}/e/{real_environment}"),
        ),
        (
            "a different second marker",
            format!("/t/{real_tenant}/x/{real_environment}"),
        ),
    ] {
        let (status, body) = manage_post(
            &router,
            &issuers,
            label,
            &serde_json::json!({
                "issuer": format!("https://vendor.example{path}"),
                "jwks": platform_jwks(),
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "a third-party issuer was refused because its path resembles a scope ({label}): \
             {body}"
        );
    }
}

/// An inline key set carrying PRIVATE key material is refused.
///
/// `trusted_keys_from_jwks` reads only the public members of each JWK, so a key set exported
/// with its private half attached parses to a usable verify key and would otherwise be stored
/// verbatim and served back by the listing. That matters because the two sides of this
/// resource are not equally privileged: registering takes `management.write_config` plus a
/// fresh sudo elevation, while READING the listing takes `management.read` alone. So a
/// private key pasted by mistake would cross a privilege boundary downward, to any auditor or
/// help-desk credential.
///
/// The mistake is ordinary rather than exotic: exporting a key set with its private half is
/// one flag in every JOSE library. And IronAuth needs only the public half, since an external
/// issuer authenticates by signing and this deployment only verifies, so there is no
/// legitimate registration this refusal costs.
#[tokio::test]
async fn an_inline_key_set_carrying_private_material_is_refused() {
    let h = Harness::start().await;
    let router = management_plane(&h).await;
    let issuers = format!("{}/external-issuers", base(&h));

    // One case per private member family: an OKP/EC private scalar, the RSA CRT factors, and a
    // symmetric key. Each is a real export shape rather than a synthetic one.
    for (label, jwks) in [
        (
            "an Ed25519 private scalar",
            r#"{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k1","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}]}"#,
        ),
        (
            "an RSA private exponent",
            r#"{"keys":[{"kty":"RSA","kid":"k2","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q","p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs","q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk"}]}"#,
        ),
        (
            // The sharp case. This RSA key carries the CRT factors `p` and `q` but NO `d`, so
            // it is a perfectly usable VERIFY key (`n` and `e` are both present) and reaches
            // the usable-key check happily. Only the private-member scan can refuse it, which
            // makes it the one fixture here that a `d`-only check would let through.
            "the RSA CRT factors without a private exponent",
            r#"{"keys":[{"kty":"RSA","kid":"k4","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs","q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk"}]}"#,
        ),
        (
            // The `k` member's own fixture. An oct key ALONE is refused by the usable-key check
            // too, so it cannot tell whether `k` is in the scanned set; here it rides alongside
            // a usable RSA public key, which makes the key set non-empty and leaves the private
            // member scan as the only thing that can refuse it. Dropping "k" from
            // PRIVATE_JWK_MEMBERS hands a symmetric secret to every management.read reader, and
            // before this fixture existed that mutation left the whole suite green.
            "a symmetric key beside a usable public one",
            r#"{"keys":[{"kty":"RSA","kid":"pub","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"},{"kty":"oct","kid":"hs","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}]}"#,
        ),
        (
            "a symmetric key alone",
            r#"{"keys":[{"kty":"oct","kid":"k3","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}]}"#,
        ),
    ] {
        let (status, body) = manage_post(
            &router,
            &issuers,
            label,
            &serde_json::json!({ "issuer": format!("https://p.example/{label}"), "jwks": jwks }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a key set carrying {label} was registered, and the listing serves it to any \
             management.read credential: {body}"
        );
        // WHICH refusal fired, not merely that one did. Several of these would also trip the
        // usable-key check, so a status-only assertion cannot tell the private-member scan from
        // it, and the message an operator needs is the one naming the private material.
        assert!(
            body.contains("private member"),
            "the refusal must name the private material rather than reporting no usable key \
             ({label}): {body}"
        );
    }

    // The positive control: the SAME shape with only the public half is registered, so the
    // refusals above are not satisfied by a route that rejects every inline key set.
    let (status, body) = manage_post(
        &router,
        &issuers,
        "public-only",
        &serde_json::json!({ "issuer": PLATFORM_ISSUER, "jwks": platform_jwks() }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "a public-only key set was refused: {body}"
    );

    // And the listing really does serve the stored document back at management.read, which is
    // what makes the refusals above matter rather than being belt and braces.
    let (status, body) = manage_get(&router, &issuers).await;
    assert_eq!(status, StatusCode::OK, "list the anchors: {body}");
    // The stored DOCUMENT, not the field name. `ExternalIssuerView.jwks` has no
    // skip_serializing_if, so `"jwks"` appears for every row including a jwks_uri-only anchor
    // with a null value: asserting on it could not fail for the reason it names.
    let stored_key =
        serde_json::from_str::<serde_json::Value>(&platform_jwks()).expect("json")["keys"][0]["x"]
            .as_str()
            .expect("the platform key's public component")
            .to_owned();
    assert!(
        body.contains(&stored_key),
        "the listing returns the stored key set VERBATIM, which is what makes the refusals \
         above matter rather than being belt and braces: {body}"
    );
}
