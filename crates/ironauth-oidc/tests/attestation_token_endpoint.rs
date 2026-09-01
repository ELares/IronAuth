// SPDX-License-Identifier: MIT OR Apache-2.0

//! Attestation-based client authentication AT THE TOKEN ENDPOINT (issue #133, PROTOTYPE).
//!
//! # Why this file exists next to `attestation_client_auth.rs`
//!
//! That file drives the verification seam directly and proves every refusal the draft names.
//! It says nothing about whether the endpoint reaches it, and "plugs into the client-auth
//! seam" is the criterion. The distinction is not academic: a module can be perfect and
//! unreachable, which is exactly what a review found twice in the vault work next door.
//!
//! What this adds is the part only the endpoint can answer:
//!
//! - the DEFAULT POSTURE: no attesters installed, so an otherwise perfect pair authenticates
//!   nobody and the answer is the same opaque `invalid_client` every other failure gives;
//! - the client's ONE registered method is enforced, so a `client_secret_basic` client cannot
//!   authenticate this way and an `attest_jwt_client_auth` client cannot present a secret;
//! - the method is NOT advertised, so discovery does not offer what no registered client can
//!   yet select;
//! - and mixing methods is refused rather than resolved.
//!
//! Over a real database (`DATABASE_URL`).

mod common;

use std::sync::Arc;

use common::{Harness, form};
use ironauth_jose::{EmissionOptions, JwkSet, SigningKey, sign_jws};
use ironauth_oidc::ClientAuthMethod;
use ironauth_oidc::attestation_client_auth::{
    ATTESTATION_POP_TYP, ATTESTATION_TYP, AttesterRegistry, TrustedAttester,
};
use serde_json::{Value, json};

const ATTESTER: &str = "https://attester.example.test";

/// A signing key from a fixed seed.
fn key(kid: &str, seed: u8) -> SigningKey {
    SigningKey::ed25519_from_seed(Some(kid.to_owned()), &[seed; 32]).expect("an ed25519 key")
}

fn jwks_of(key: &SigningKey) -> Vec<u8> {
    JwkSet::from_signing_keys([key])
        .expect("a jwk set")
        .to_json()
        .expect("jwks json")
        .into_bytes()
}

fn public_jwk(key: &SigningKey) -> Value {
    let set: Value = serde_json::from_slice(&jwks_of(key)).expect("jwks parses");
    set["keys"][0].clone()
}

fn jwt(key: &SigningKey, typ: &str, claims: &Value) -> String {
    sign_jws(
        key,
        serde_json::to_vec(claims)
            .expect("claims serialize")
            .as_slice(),
        &EmissionOptions::new().with_typ(typ), // invariant-allow: typ-via-declaration -- the DRAFT's two media types, dictated by draft-ietf-oauth-attestation-based-client-auth, not IronAuth profiles
    )
    .expect("sign")
}

/// The harness clock as epoch seconds, so the fixtures are live under it.
fn now_secs(harness: &Harness) -> i64 {
    i64::try_from(
        harness
            .state()
            .now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a time after the epoch")
            .as_secs(),
    )
    .expect("the epoch offset fits an i64")
}

/// The attestation an honest attester mints for `client`, binding `instance`'s key.
fn attestation(
    attester_key: &SigningKey,
    instance: &SigningKey,
    client: &str,
    audience: &str,
    now: i64,
) -> String {
    jwt(
        attester_key,
        ATTESTATION_TYP,
        &json!({
            "iss": ATTESTER,
            "sub": client,
            "aud": audience,
            "iat": now - 10,
            "exp": now + 600,
            "cnf": { "jwk": public_jwk(instance) },
        }),
    )
}

/// The proof the instance mints with the key the attestation bound.
fn proof(instance: &SigningKey, client: &str, audience: &str, now: i64) -> String {
    jwt(
        instance,
        ATTESTATION_POP_TYP,
        &json!({
            "iss": client,
            "aud": audience,
            "jti": "pop-endpoint-0001",
            "iat": now - 5,
            "exp": now + 60,
        }),
    )
}

/// A registry trusting one attester.
fn registry(attester_key: &SigningKey) -> Arc<AttesterRegistry> {
    Arc::new(AttesterRegistry::new().with(
        TrustedAttester::from_jwks(ATTESTER, &jwks_of(attester_key)).expect("a trusted attester"),
    ))
}

/// The client-credentials form for `client`.
fn cc_form(client: &str) -> String {
    form(&[("grant_type", "client_credentials"), ("client_id", client)])
}

#[tokio::test]
async fn an_attested_instance_gets_a_token_from_the_client_credentials_grant() {
    let mut harness = Harness::start().await;
    let attester_key = key("attester-kid", 11);
    let instance = key("instance-kid", 22);
    harness.install_attesters(registry(&attester_key));

    let client = harness
        .create_confidential_client(ClientAuthMethod::AttestJwt)
        .await
        .0
        .to_string();
    let audience = harness.issuer().to_owned();
    let now = now_secs(&harness);

    let (status, _headers, body) = harness
        .token_attested(
            &cc_form(&client),
            Some(&attestation(
                &attester_key,
                &instance,
                &client,
                &audience,
                now,
            )),
            Some(&proof(&instance, &client, &audience, now)),
        )
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "an attested instance holding no secret should get its own token: {body}"
    );
    assert!(
        body.contains("access_token"),
        "and the response carries one: {body}"
    );
}

#[tokio::test]
async fn the_default_posture_authenticates_nobody_even_with_a_perfect_pair() {
    // THE DEFAULT, and the reason the prototype is safe to ship dark: no registry installed,
    // so the seam refuses before it reads anything the caller sent. The pair here is the SAME
    // one the test above authenticates with, which is what makes this about the posture rather
    // than about a broken fixture.
    let harness = Harness::start().await;
    let attester_key = key("attester-kid", 11);
    let instance = key("instance-kid", 22);

    let client = harness
        .create_confidential_client(ClientAuthMethod::AttestJwt)
        .await
        .0
        .to_string();
    let audience = harness.issuer().to_owned();
    let now = now_secs(&harness);

    let (status, _headers, body) = harness
        .token_attested(
            &cc_form(&client),
            Some(&attestation(
                &attester_key,
                &instance,
                &client,
                &audience,
                now,
            )),
            Some(&proof(&instance, &client, &audience, now)),
        )
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::UNAUTHORIZED,
        "with no attester trusted, nobody authenticates: {body}"
    );
    assert!(
        body.contains("invalid_client"),
        "and it is the same opaque refusal every other failure gives: {body}"
    );
}

#[tokio::test]
async fn a_client_registered_for_a_secret_cannot_authenticate_by_attestation() {
    // The client's ONE registered method, enforced exactly as every other path enforces it.
    // Without this an attester could authenticate any client whose id it could name, including
    // ones the operator registered for a secret.
    let mut harness = Harness::start().await;
    let attester_key = key("attester-kid", 11);
    let instance = key("instance-kid", 22);
    harness.install_attesters(registry(&attester_key));

    let (client, _secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client = client.to_string();
    let audience = harness.issuer().to_owned();
    let now = now_secs(&harness);

    let (status, _headers, body) = harness
        .token_attested(
            &cc_form(&client),
            Some(&attestation(
                &attester_key,
                &instance,
                &client,
                &audience,
                now,
            )),
            Some(&proof(&instance, &client, &audience, now)),
        )
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::UNAUTHORIZED,
        "a secret-registered client must not be attestable: {body}"
    );
}

#[tokio::test]
async fn an_attestation_registered_client_cannot_fall_back_to_a_secret() {
    // The other direction, and the one that matters more: if a client registered for the
    // PROTOTYPE method could still authenticate with a secret, enabling the experiment would
    // have widened the surface rather than added one.
    let mut harness = Harness::start().await;
    let attester_key = key("attester-kid", 11);
    harness.install_attesters(registry(&attester_key));

    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::AttestJwt)
        .await;
    let form = form(&[
        ("grant_type", "client_credentials"),
        ("client_id", client.to_string().as_str()),
        ("client_secret", secret.as_str()),
    ]);
    let (status, _headers, body) = harness.token(&form).await;
    assert_eq!(
        status,
        axum::http::StatusCode::UNAUTHORIZED,
        "an attestation-registered client must not authenticate with a secret: {body}"
    );
}

#[tokio::test]
async fn presenting_an_attestation_and_a_secret_is_refused_as_two_methods() {
    // RFC 6749 section 2.3 forbids more than one authentication method on a request, and a
    // caller presenting both has not decided what it is. Resolving it in either direction
    // would be a downgrade an attacker chooses.
    let mut harness = Harness::start().await;
    let attester_key = key("attester-kid", 11);
    let instance = key("instance-kid", 22);
    harness.install_attesters(registry(&attester_key));

    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::AttestJwt)
        .await;
    let client = client.to_string();
    let audience = harness.issuer().to_owned();
    let now = now_secs(&harness);
    let both = form(&[
        ("grant_type", "client_credentials"),
        ("client_id", client.as_str()),
        ("client_secret", secret.as_str()),
    ]);

    let (status, _headers, body) = harness
        .token_attested(
            &both,
            Some(&attestation(
                &attester_key,
                &instance,
                &client,
                &audience,
                now,
            )),
            Some(&proof(&instance, &client, &audience, now)),
        )
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "two methods is a bad request, not a choice: {body}"
    );
    assert!(body.contains("invalid_request"), "{body}");
}

#[tokio::test]
async fn one_header_without_the_other_is_not_an_attestation_attempt() {
    // Half a pair is malformed, not a partial attempt to be helped along. Treating it as one
    // would give an unauthenticated prober a way to tell the method's presence from its
    // absence: the request would take a different path and could answer differently.
    let mut harness = Harness::start().await;
    let attester_key = key("attester-kid", 11);
    let instance = key("instance-kid", 22);
    harness.install_attesters(registry(&attester_key));

    let client = harness
        .create_confidential_client(ClientAuthMethod::AttestJwt)
        .await
        .0
        .to_string();
    let audience = harness.issuer().to_owned();
    let now = now_secs(&harness);

    let (only_attestation, _h, body_a) = harness
        .token_attested(
            &cc_form(&client),
            Some(&attestation(
                &attester_key,
                &instance,
                &client,
                &audience,
                now,
            )),
            None,
        )
        .await;
    let (only_proof, _h, body_p) = harness
        .token_attested(
            &cc_form(&client),
            None,
            Some(&proof(&instance, &client, &audience, now)),
        )
        .await;
    assert_eq!(
        only_attestation,
        axum::http::StatusCode::UNAUTHORIZED,
        "{body_a}"
    );
    assert_eq!(only_proof, axum::http::StatusCode::UNAUTHORIZED, "{body_p}");
    assert_eq!(
        only_attestation, only_proof,
        "and the two halves answer identically, so neither is an oracle"
    );
}

#[tokio::test]
async fn discovery_does_not_advertise_the_prototype_method() {
    // A method discovery offers is one a client may register for, and no client should
    // register for a draft surface that is off in every deployment that has not opted in.
    // `ClientAuthMethod::ALL` is the single source discovery reads.
    let mut harness = Harness::start().await;
    harness.install_attesters(registry(&key("attester-kid", 11)));

    let scope = harness.scope();
    let request = axum::http::Request::builder()
        .method("GET")
        .uri(format!(
            "/t/{}/e/{}/.well-known/openid-configuration",
            scope.tenant(),
            scope.environment()
        ))
        .body(axum::body::Body::empty())
        .expect("request builds");
    let (status, _headers, body) = harness.send(request).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert!(
        !body.contains("attest_jwt_client_auth"),
        "the prototype method must not be advertised, even where it is armed: {body}"
    );
    // The control: discovery DOES list the methods that are supported, so the assertion above
    // is not passing against an empty or missing field.
    assert!(
        body.contains("client_secret_basic"),
        "discovery still advertises the supported methods: {body}"
    );
}

#[tokio::test]
async fn a_deployment_with_the_prototype_off_ignores_the_headers_entirely() {
    // "Nothing changes for a deployment that has not enabled it" has to mean the headers are
    // INVISIBLE, not merely inert. The first version ran the mixing refusal before consulting
    // the registry, so an unarmed deployment answered 400 to a request with perfectly good
    // Basic credentials that happened to carry these headers -- where it had answered 200.
    let harness = Harness::start().await;
    let attester_key = key("attester-kid", 11);
    let instance = key("instance-kid", 22);

    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client = client.to_string();
    let audience = harness.issuer().to_owned();
    let now = now_secs(&harness);
    let basic = format!(
        "Basic {}",
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("{client}:{secret}")
        )
    );

    // The control: the same credential without the headers.
    let (control, _headers, control_body) = harness
        .token_with_auth(&form(&[("grant_type", "client_credentials")]), Some(&basic))
        .await;

    // And now WITH them, on a deployment that never armed the prototype.
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/token")
        .header(
            axum::http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .header(axum::http::header::AUTHORIZATION, &basic)
        .header(
            "OAuth-Client-Attestation",
            attestation(&attester_key, &instance, &client, &audience, now),
        )
        .header(
            "OAuth-Client-Attestation-PoP",
            proof(&instance, &client, &audience, now),
        )
        .body(axum::body::Body::from(form(&[(
            "grant_type",
            "client_credentials",
        )])))
        .expect("request builds");
    let (with_headers, _headers, body) = harness.send(request).await;

    assert_eq!(
        with_headers, control,
        "an unarmed deployment must answer identically with and without the headers: \
         {body} vs {control_body}"
    );
}

#[tokio::test]
async fn presenting_an_attestation_and_a_client_assertion_is_refused_as_two_methods() {
    // The half the first version missed. It named the Authorization header and `client_secret`
    // and stopped there, so an attestation presented alongside a `client_assertion` was
    // silently RESOLVED in favour of the attestation -- which is the downgrade the refusal
    // exists to prevent, chosen by whoever sends the request.
    let mut harness = Harness::start().await;
    let attester_key = key("attester-kid", 11);
    let instance = key("instance-kid", 22);
    harness.install_attesters(registry(&attester_key));

    let client = harness
        .create_confidential_client(ClientAuthMethod::AttestJwt)
        .await
        .0
        .to_string();
    let audience = harness.issuer().to_owned();
    let now = now_secs(&harness);
    let both = form(&[
        ("grant_type", "client_credentials"),
        ("client_id", client.as_str()),
        (
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ),
        ("client_assertion", "not.a.real.assertion"),
    ]);

    let (status, _headers, body) = harness
        .token_attested(
            &both,
            Some(&attestation(
                &attester_key,
                &instance,
                &client,
                &audience,
                now,
            )),
            Some(&proof(&instance, &client, &audience, now)),
        )
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "an attestation alongside a client assertion is two methods: {body}"
    );
    assert!(body.contains("invalid_request"), "{body}");
}

#[tokio::test]
async fn a_bearer_authorization_header_is_not_a_second_method() {
    // The over-broad direction of the same check. `parse_presented` deliberately ignores a
    // non-Basic `Authorization` -- mTLS client auth and bearer are not client-authentication
    // inputs -- so firing on ANY scheme would have made this a 400 where the secret path
    // ignores the header.
    let mut harness = Harness::start().await;
    let attester_key = key("attester-kid", 11);
    let instance = key("instance-kid", 22);
    harness.install_attesters(registry(&attester_key));

    let client = harness
        .create_confidential_client(ClientAuthMethod::AttestJwt)
        .await
        .0
        .to_string();
    let audience = harness.issuer().to_owned();
    let now = now_secs(&harness);

    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/token")
        .header(
            axum::http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .header(axum::http::header::AUTHORIZATION, "Bearer irrelevant")
        .header(
            "OAuth-Client-Attestation",
            attestation(&attester_key, &instance, &client, &audience, now),
        )
        .header(
            "OAuth-Client-Attestation-PoP",
            proof(&instance, &client, &audience, now),
        )
        .body(axum::body::Body::from(cc_form(&client)))
        .expect("request builds");
    let (status, _headers, body) = harness.send(request).await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "a bearer header is not a client credential and must not make this two methods: {body}"
    );
}
