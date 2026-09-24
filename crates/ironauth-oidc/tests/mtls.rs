// SPDX-License-Identifier: MIT OR Apache-2.0

//! The self-signed mTLS client-authentication suite (issue #159), over a real
//! database.
//!
//! Exercises `self_signed_tls_client_auth` end to end through the reusable
//! [`ironauth_oidc::authenticate_client`] seam (the SAME seam the token endpoint
//! uses): the registered certificate authenticates, ANY other certificate is the
//! opaque `invalid_client` (a substitution, however well-formed, is not the
//! registered one), an expired certificate is rejected, a certificate-less
//! request is rejected, and a certificate-less registration is a store-level
//! conflict (the CHECK refuses it loudly, mirroring the keyless `private_key_jwt`
//! discipline).

mod common;

use base64::Engine as _;
use std::time::{Duration, SystemTime};

use axum::http::StatusCode;

/// The proxy's escaped certificate form: percent-encode every byte (a header value
/// cannot carry the PEM's newlines).
fn percent_escape(pem: &str) -> String {
    pem.as_bytes()
        .iter()
        .fold(String::with_capacity(pem.len() * 3), |mut out, byte| {
            use std::fmt::Write as _;
            let _ = write!(out, "%{byte:02X}");
            out
        })
}

use common::Harness;
use ironauth_oidc::{ClientAuthInputs, ClientAuthMethod, authenticate_client};
use rcgen::{CertificateParams, KeyPair, KeyUsagePurpose};

/// The harness's deterministic clock starts at the UNIX epoch; a test advances it to
/// the REAL now so the auth instant lands inside every cert's validity window.
fn advance_to_now(h: &mut Harness) {
    let now = SystemTime::now() // invariant-allow: time-via-env (the harness clock is
        // advanced to REAL now so the auth instant lands inside the test certs' validity
        // windows; the certs themselves are anchored to the same real wall-clock).
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("post-epoch");
    h.clock().advance(now);
}

/// A fresh self-signed client certificate (its own issuer), valid for an hour
/// from the harness's now, PEM-encoded.
fn fresh_leaf_pem() -> String {
    leaf_pem(
        SystemTime::now() - Duration::from_secs(60), // invariant-allow: time-via-env
        SystemTime::now() + Duration::from_secs(3600), // invariant-allow: time-via-env
    )
}

/// A leaf certificate valid over `[not_before, not_after]`, PEM-encoded.
fn leaf_pem(not_before: SystemTime, not_after: SystemTime) -> String {
    // invariant-allow: time-via-env on the lines below: test certificate validity
    // windows are anchored to real wall-clock, as the advance helper documents.
    let key = KeyPair::generate().expect("the test key generates");
    let mut params = CertificateParams::default();
    params.not_before = not_before.into(); // invariant-allow: time-via-env
    params.not_after = not_after.into();
    params.not_after = not_after.into();
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let cert = params
        .self_signed(&key)
        .expect("the test certificate generates");
    cert.pem()
}

/// Drive the seam with `certificate_pem` (or none) for `client_id`.
async fn authenticate(
    h: &Harness,
    client_id: &str,
    certificate_pem: Option<&str>,
) -> Result<(), ironauth_oidc::ClientAuthError> {
    let inputs = ClientAuthInputs {
        authorization: None,
        client_id: Some(client_id),
        client_secret: None,
        client_assertion: None,
        client_assertion_type: None,
        client_certificate: certificate_pem,
    };
    authenticate_client(h.state(), h.scope(), inputs)
        .await
        .map(|_| ())
}

/// The registered certificate authenticates; the client id is the wire claim.
#[tokio::test]
async fn the_registered_certificate_authenticates() {
    let mut h = Harness::start().await;
    advance_to_now(&mut h);
    let cert = fresh_leaf_pem();
    let client = h
        .create_self_signed_mtls_client(&cert)
        .await
        .expect("the mTLS client registers");
    authenticate(&h, &client.to_string(), Some(&cert))
        .await
        .expect("the registered certificate authenticates");
}

/// ANY other certificate is rejected: the substitution, however well-formed, is
/// not the registered one.
#[tokio::test]
async fn a_different_certificate_is_rejected() {
    let mut h = Harness::start().await;
    advance_to_now(&mut h);
    let registered = fresh_leaf_pem();
    let substituted = fresh_leaf_pem();
    assert_ne!(registered, substituted, "two fresh leaves differ");
    let client = h
        .create_self_signed_mtls_client(&registered)
        .await
        .expect("the mTLS client registers");
    let result = authenticate(&h, &client.to_string(), Some(&substituted)).await;
    assert!(
        matches!(
            result,
            Err(ironauth_oidc::ClientAuthError::InvalidClient { .. })
        ),
        "a substituted certificate must fail closed: {result:?}"
    );
}

/// An expired certificate is rejected even when it is the registered one: the
/// method demands validity at the request instant as well as DER equality.
#[tokio::test]
async fn an_expired_registered_certificate_is_rejected() {
    let mut h = Harness::start().await;
    advance_to_now(&mut h);
    let expired = leaf_pem(
        SystemTime::now() - Duration::from_secs(7200), // invariant-allow: time-via-env
        SystemTime::now() - Duration::from_secs(3600), // invariant-allow: time-via-env
    );
    let client = h
        .create_self_signed_mtls_client(&expired)
        .await
        .expect("the mTLS client registers");
    let result = authenticate(&h, &client.to_string(), Some(&expired)).await;
    assert!(
        matches!(
            result,
            Err(ironauth_oidc::ClientAuthError::InvalidClient { .. })
        ),
        "an expired registered certificate must fail closed: {result:?}"
    );
}

/// A certificate-less request is rejected for a method that requires one.
#[tokio::test]
async fn a_certificate_less_request_is_rejected() {
    let mut h = Harness::start().await;
    advance_to_now(&mut h);
    let cert = fresh_leaf_pem();
    let client = h
        .create_self_signed_mtls_client(&cert)
        .await
        .expect("the mTLS client registers");
    let result = authenticate(&h, &client.to_string(), None).await;
    assert!(
        matches!(
            result,
            Err(ironauth_oidc::ClientAuthError::InvalidClient { .. })
        ),
        "a certificate-less request must fail closed: {result:?}"
    );
}

/// END TO END THROUGH THE TOKEN ENDPOINT: a client registered for
/// `self_signed_tls_client_auth` exchanges client credentials over the stamped
/// certificate header, and a substituted certificate is refused.
#[tokio::test]
async fn the_token_endpoint_authenticates_an_mtls_client_end_to_end() {
    let mut h = Harness::start().await;
    advance_to_now(&mut h);
    let cert = fresh_leaf_pem();
    let client = h
        .create_self_signed_mtls_client(&cert)
        .await
        .expect("the mTLS client registers");
    let client_id = client.to_string();
    let body = common::form(&[
        ("grant_type", "client_credentials"),
        ("client_id", &client_id),
    ]);
    // The proxy's escaped form: the PEM's newlines cannot ride a header value.
    let escaped = percent_escape(&cert);
    let (status, _, response) = h.token_with_certificate(&body, &escaped).await;
    let diagnostics = h.client_auth_diagnostics(&client_id).await;
    eprintln!(
        "mtls diagnostics: {:?}",
        diagnostics
            .iter()
            .map(|d| d.failure_reason.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        status,
        StatusCode::OK,
        "the mTLS client exchanges tokens: {response}"
    );

    let substituted = fresh_leaf_pem();
    let escaped_sub = percent_escape(&substituted);
    let (status, _, response) = h.token_with_certificate(&body, &escaped_sub).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a substituted certificate is refused at the token endpoint: {response}"
    );
}

/// THE BOUND-TOKEN CRITERION (RFC 8705 section 3): a client-credentials exchange
/// over an mTLS-authenticated connection mints an access token bound via cnf
/// x5t#S256, and introspection surfaces the binding.
#[tokio::test]
async fn an_mtls_exchange_mints_a_certificate_bound_token() {
    let mut h = Harness::start().await;
    advance_to_now(&mut h);
    let cert = fresh_leaf_pem();
    let client = h
        .create_self_signed_mtls_client(&cert)
        .await
        .expect("the mTLS client registers");
    let client_id = client.to_string();
    let body = common::form(&[
        ("grant_type", "client_credentials"),
        ("client_id", &client_id),
    ]);
    let escaped = percent_escape(&cert);
    let (status, _, response) = h.token_with_certificate(&body, &escaped).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the mTLS exchange succeeds: {response}"
    );
    let tokens: serde_json::Value = serde_json::from_str(&response).expect("token json");
    let access = tokens["access_token"].as_str().expect("access token");

    // Introspect as a SECOND confidential client (the mTLS client's method cannot
    // authenticate to /introspect; the introspection credential is its own).
    let (introspector, secret) = h
        .create_confidential_client(ironauth_oidc::ClientAuthMethod::Basic)
        .await;
    let thumbprint = ironauth_jose::mtls::parse_presented_certificate(&cert)
        .expect("the cert parses")
        .thumbprint;
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/introspect")
        .header(
            axum::http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .header(
            axum::http::header::AUTHORIZATION,
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD
                    .encode(format!("{introspector}:{secret}"))
            ),
        )
        .body(axum::body::Body::from(common::form(&[("token", access)])))
        .expect("request builds");
    let (status, _, body) = h.send(request).await;
    assert_eq!(status, StatusCode::OK, "introspect: {body}");
    let introspected: serde_json::Value = serde_json::from_str(&body).expect("introspection json");
    assert_eq!(introspected["active"], true, "the token is active: {body}");
    assert_eq!(
        introspected["cnf"]["x5t#S256"].as_str(),
        Some(thumbprint.as_str()),
        "introspection reports the certificate thumbprint: {body}"
    );
}

/// THE JWT FORM OF THE BINDING: under a JWT access-token format, the minted token
/// itself carries `cnf.x5t#S256`, not only the introspection record.
#[tokio::test]
async fn an_mtls_exchange_mints_a_jwt_bound_via_its_cnf_claim() {
    let mut h = Harness::start_with(ironauth_config::OidcConfig {
        default_access_token_format: ironauth_config::TokenFormat::AtJwt,
        ..ironauth_config::OidcConfig::default()
    })
    .await;
    advance_to_now(&mut h);
    let cert = fresh_leaf_pem();
    let client = h
        .create_self_signed_mtls_client(&cert)
        .await
        .expect("the mTLS client registers");
    let client_id = client.to_string();
    let body = common::form(&[
        ("grant_type", "client_credentials"),
        ("client_id", &client_id),
    ]);
    let escaped = percent_escape(&cert);
    let (status, _, response) = h.token_with_certificate(&body, &escaped).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the mTLS exchange succeeds: {response}"
    );
    let tokens: serde_json::Value = serde_json::from_str(&response).expect("token json");
    let access = tokens["access_token"].as_str().expect("access token");

    // The at+jwt token's payload carries the binding.
    let payload = access.split('.').nth(1).expect("the payload segment");
    let claims: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .expect("the payload decodes"),
    )
    .expect("the payload is json");
    let thumbprint = ironauth_jose::mtls::parse_presented_certificate(&cert)
        .expect("the cert parses")
        .thumbprint;
    assert_eq!(
        claims["cnf"]["x5t#S256"].as_str(),
        Some(thumbprint.as_str()),
        "the minted JWT embeds cnf x5t#S256: {claims}"
    );
}

/// A test CA + leaf under it (the PKI method's fixtures).
fn test_ca_and_leaf() -> (String, String) {
    let ca_key = KeyPair::generate().expect("ca key");
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca = ca_params.self_signed(&ca_key).expect("the CA generates");
    let leaf_key = KeyPair::generate().expect("leaf key");
    let mut leaf_params = CertificateParams::default();
    leaf_params.not_before = (SystemTime::now() - Duration::from_secs(60)).into(); // invariant-allow: time-via-env
    leaf_params.not_after = (SystemTime::now() + Duration::from_secs(3600)).into(); // invariant-allow: time-via-env
    let leaf = leaf_params
        .signed_by(&leaf_key, &ca, &ca_key)
        .expect("the leaf generates");
    (ca.pem(), leaf.pem())
}

/// THE PKI METHOD (RFC 8705 `tls_client_auth`): a chain validating against the
/// deployment's trust anchors with a matching subject authenticates; a foreign CA
/// and a subject mismatch fail closed.
#[tokio::test]
async fn the_pki_method_validates_the_chain_and_subject() {
    let (ca_pem, leaf_pem) = test_ca_and_leaf();
    let mut h = Harness::start().await;
    advance_to_now(&mut h);
    h.arm_mtls_anchors(&[ca_pem]);
    let subject = ironauth_jose::mtls::certificate_subject_dn(
        &ironauth_jose::mtls::parse_presented_certificate(&leaf_pem)
            .expect("parses")
            .certificate(),
    );
    let client = h
        .create_tls_client_auth_client(&subject)
        .await
        .expect("the PKI client registers");

    let body = common::form(&[
        ("grant_type", "client_credentials"),
        ("client_id", &client.to_string()),
    ]);
    let escaped = percent_escape(&leaf_pem);
    let (status, _, response) = h.token_with_certificate(&body, &escaped).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the PKI method authenticates: {response}"
    );

    // A leaf from a DIFFERENT CA is refused by THIS deployment's anchors, even with a
    // registered subject that matches the attacker's leaf.
    let (_, other_leaf) = test_ca_and_leaf();
    let other_subject = ironauth_jose::mtls::certificate_subject_dn(
        &ironauth_jose::mtls::parse_presented_certificate(&other_leaf)
            .expect("parses")
            .certificate(),
    );
    let attacker = h
        .create_tls_client_auth_client(&other_subject)
        .await
        .expect("the attacker's client registers");
    let body_attacker = common::form(&[
        ("grant_type", "client_credentials"),
        ("client_id", &attacker.to_string()),
    ]);
    let (status, _, response) = h
        .token_with_certificate(&body_attacker, &percent_escape(&other_leaf))
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a foreign-CA leaf is refused: {response}"
    );

    // A subject mismatch on the SAME trust anchors is refused: the registered client
    // cannot authenticate with a different-subject leaf.
    let (_, other_leaf) = test_ca_and_leaf();
    let (status, _, response) = h
        .token_with_certificate(&body, &percent_escape(&other_leaf))
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a subject mismatch is refused: {response}"
    );
}

/// THE DECLARATION (RFC 8705 section 5): a client registering
/// `use_mtls_endpoint_aliases: true` has the declaration stored and readable
/// through the auth record.
#[tokio::test]
async fn the_use_mtls_endpoint_aliases_declaration_is_stored() {
    let mut h = Harness::start().await;
    advance_to_now(&mut h);
    let cert = fresh_leaf_pem();
    let client = h
        .create_self_signed_mtls_client(&cert)
        .await
        .expect("the mTLS client registers");
    let record = h
        .store()
        .scoped(h.scope())
        .clients()
        .auth_record(&client)
        .await
        .expect("the record reads");
    assert!(
        !record.use_mtls_endpoint_aliases,
        "the default is no declaration"
    );

    // A DYNAMIC registration declaring the flag stores it, readable back through
    // the same record.
    let (actor, corr) = h.seeding_actor();
    let declared = h
        .store()
        .scoped(h.scope())
        .acting(actor, corr)
        .clients()
        .register_dynamic(
            h.env(),
            ironauth_store::NewDynamicClient {
                display_name: "declaring client",
                auth_method: "none",
                secret_hash: None,
                redirect_uris: &["https://client.example/callback".to_owned()],
                application_type: "web",
                id_token_signed_response_alg: "EdDSA",
                jwks: None,
                jwks_uri: None,
                token_endpoint_auth_signing_alg: None,
                tls_client_auth_cert: None,
                tls_client_auth_subject_dn: None,
                use_mtls_endpoint_aliases: true,
                registration_access_token_hash: "hash",
                registration_uri_base: "https://issuer.test/connect/register",
                quarantined: false,
                dcr_policy_chain: None,
            },
            None,
        )
        .await
        .expect("the dynamic registration succeeds");
    let record = h
        .store()
        .scoped(h.scope())
        .clients()
        .auth_record(&declared.id)
        .await
        .expect("the record reads");
    assert!(
        record.use_mtls_endpoint_aliases,
        "the declaration is stored and readable"
    );
}

/// The method's registered method is the ONE the seam enforces: a client
/// registered for mTLS cannot authenticate any other way, and the out-of-band
/// diagnostic records the certificate failure (the wire stays opaque).
#[tokio::test]
async fn the_seam_enforces_the_registered_method_and_records_the_diagnostic() {
    let mut h = Harness::start().await;
    advance_to_now(&mut h);
    let cert = fresh_leaf_pem();
    let client = h
        .create_self_signed_mtls_client(&cert)
        .await
        .expect("the mTLS client registers");
    let client_id = client.to_string();
    let substituted = fresh_leaf_pem();
    let result = authenticate(&h, &client_id, Some(&substituted)).await;
    assert!(result.is_err(), "the substitution fails");
    let diagnostics = h.client_auth_diagnostics(&client_id).await;
    assert!(
        diagnostics
            .iter()
            .any(|record| record.failure_reason == "bad_certificate"),
        "the out-of-band diagnostic records the certificate failure"
    );
    assert_eq!(
        ClientAuthMethod::parse("self_signed_tls_client_auth"),
        Some(ClientAuthMethod::SelfSignedTlsClientAuth),
        "the wire method parses"
    );
}
