//! The SP metadata document over the real router (issue #139).
//!
//! # What it closes
//!
//! The start endpoint signs every `AuthnRequest` with the connection's key and nothing published
//! the public half, so an identity provider configured to verify had nothing to verify against.
//! The headline test here drives both ends: fetch the metadata, take the certificate out of it,
//! and verify a real request this deployment signed -- which is exactly what the far side does,
//! and the only check that proves the document is about the right key.
#![cfg(feature = "testing")]

mod common;

use base64::Engine as _;
use common::Harness;
use ironauth_env::Env;
use ironauth_jose::xmldsig::test_util::XmlTestKey;
use ironauth_store::{
    CorrelationId, NewSamlCertificate, NewSamlConnection, NewSamlSpKey, OrganizationId,
    SamlCertificateId, SamlConnectionId, SamlKeyKind, SamlSpKeyId,
};
use serde_json::json;

const ISSUER: &str = "urn:idp";
const NAMEID_FORMAT: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

struct Wired {
    connection: SamlConnectionId,
    audience: String,
    start_path: String,
}

/// Create a connection with a pinned identity-provider certificate, and optionally the SP
/// signing key this deployment needs to start a flow.
async fn wire(harness: &Harness, with_sp_key: bool) -> Wired {
    wire_at(harness, with_sp_key, "https://idp.example/sso").await
}

/// [`wire`] with the identity provider's SSO URL chosen by the caller.
async fn wire_at(harness: &Harness, with_sp_key: bool, idp_sso_url: &str) -> Wired {
    let env = harness.env().clone();
    let scope = harness.scope();
    let organization = OrganizationId::generate(&env, &scope);
    harness
        .db()
        .control_store()
        .management()
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .organizations(scope)
        .create(&env, &organization, now_micros(&env), "Globex", None)
        .await
        .expect("create organization");

    let connection = SamlConnectionId::generate(&env, &scope);
    let acs_path = format!(
        "/t/{}/e/{}/saml/acs/{connection}",
        scope.tenant(),
        scope.environment()
    );
    let start_path = format!(
        "/t/{}/e/{}/saml/start/{connection}",
        scope.tenant(),
        scope.environment()
    );
    let acs_url = format!("https://ironauth.example{acs_path}");
    let audience = format!("https://ironauth.example/saml/{connection}/metadata");

    let acting = harness
        .db()
        .control_store()
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env));
    acting
        .saml_connections()
        .create(
            &env,
            NewSamlConnection {
                id: &connection,
                organization_id: &organization,
                display_name: "Okta",
                idp_entity_id: ISSUER,
                idp_sso_url,
                sp_entity_id: &audience,
                acs_url: &acs_url,
                // FALSE, WHICH IS THE POINT OF THIS FILE. Every other SAML suite opts in, because
                // without an AuthnRequest that was the only reachable mode. Here the connection
                // refuses unsolicited responses, so a response is only ever accepted because a
                // request was issued for it.
                allow_unsolicited: false,
                clock_skew_secs: 30,
                max_assertion_age_secs: 300,
                nameid_format: NAMEID_FORMAT,
                attribute_mapping: &json!({}),
                require_encrypted_assertion: false,
            },
            None,
            None,
        )
        .await
        .expect("create the connection");

    let key = XmlTestKey::generate();
    let now = now_micros(&env);
    acting
        .saml_connections()
        .pin_certificate(
            &env,
            NewSamlCertificate {
                id: &SamlCertificateId::generate(&env, &scope),
                connection_id: &connection,
                key_kind: SamlKeyKind::EcdsaP256,
                public_key: &key.public_point(),
                rsa_exponent: None,
                certificate_der: &[0x30, 0x82, 0x01],
                fingerprint_sha256: &std::iter::repeat_n(0x11_u8, 32).collect::<Vec<_>>(),
                not_before_unix_micros: now - 1_000_000,
                not_after_unix_micros: now + 86_400_000_000,
            },
            None,
            None,
        )
        .await
        .expect("pin the certificate");

    if with_sp_key {
        provision_key(harness, &connection).await;
    }

    Wired {
        connection,
        audience,
        start_path,
    }
}

/// Mint the SP signing key the connection needs to start a flow.
///
/// SPLIT OUT OF `wire` because it is the one thing a test varies, and because #140 will replace
/// this call with an admin endpoint: keeping it in one place is what makes that a one-line
/// change rather than a hunt.
async fn provision_key(harness: &Harness, connection: &SamlConnectionId) {
    let created_at = now_micros(harness.env());
    provision_key_at(harness, connection, created_at).await;
}

/// Provision the SP signing key with a CALLER-CHOSEN creation instant.
///
/// THE INSTANT IS A PARAMETER BECAUSE THE HARNESS CLOCK DOES NOT MOVE. A test that provisions
/// "now" and then fetches cannot tell a window anchored to the key from one anchored to the
/// request: under a frozen clock those are the same number, so the assertion passes either way.
/// Backdating the key separates them.
async fn provision_key_at(
    harness: &Harness,
    connection: &SamlConnectionId,
    created_at_unix_micros: i64,
) {
    let env = harness.env().clone();
    let scope = harness.scope();
    let der = ironauth_jose::generate_rsa_pkcs1_der(env.entropy()).expect("generate the SP key");
    harness
        .db()
        .control_store()
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .saml_connections()
        .provision_sp_key(
            &env,
            NewSamlSpKey {
                id: &SamlSpKeyId::generate(&env, &scope),
                connection_id: connection,
                algorithm: "rsa-sha256",
                key_material: &der,
                created_at_unix_micros,
            },
            None,
        )
        .await
        .expect("provision the SP signing key");
}

fn now_micros(env: &Env) -> i64 {
    i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("after epoch")
            .as_micros(),
    )
    .expect("fits i64")
}

/// `GET path` through the real router.
async fn get(
    harness: &Harness,
    path: &str,
) -> (axum::http::StatusCode, axum::http::HeaderMap, String) {
    let request = axum::http::Request::builder()
        .method("GET")
        .uri(path)
        .body(axum::body::Body::empty())
        .expect("request builds");
    harness.send(request).await
}

/// Every header a response carries, as a comparable list.
fn header_shape(headers: &axum::http::HeaderMap) -> Vec<(String, String)> {
    let mut shape: Vec<(String, String)> = headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect();
    shape.sort();
    shape
}

/// The value of `name` in a query string, still percent-encoded.
fn param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == name).then(|| value.to_owned())
    })
}

fn percent_decode(raw: &str) -> Vec<u8> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).expect("ascii");
            out.push(u8::from_str_radix(hex, 16).expect("hex"));
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    out
}

/// The certificate inside a metadata document, decoded.
fn certificate_der(document: &str) -> Vec<u8> {
    let encoded = document
        .split("<ds:X509Certificate>")
        .nth(1)
        .and_then(|rest| rest.split("</ds:X509Certificate>").next())
        .expect("the document carries a certificate");
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .expect("standard base64")
}

#[tokio::test]
async fn the_published_certificate_verifies_a_request_this_deployment_signed() {
    // BOTH ENDS, which is the only check that proves the document is about the right key. A
    // metadata document carrying a well-formed certificate for a DIFFERENT key passes every
    // structural assertion and fails every real sign-in, diagnosed at the identity provider as
    // a signature problem with no hint that the metadata is where to look.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, true).await;
    let metadata_path = format!(
        "/t/{}/e/{}/saml/metadata/{}",
        harness.scope().tenant(),
        harness.scope().environment(),
        wired.connection
    );

    let (status, headers, document) = get(&harness, &metadata_path).await;
    assert_eq!(status, 200, "{document}");
    assert_eq!(
        headers
            .get(axum::http::header::CONTENT_TYPE)
            .map(|value| value.to_str().unwrap_or_default()),
        Some("application/samlmetadata+xml")
    );

    // THE KEY OUT OF THE PUBLISHED CERTIFICATE, read by the same function that reads a
    // certificate an operator pins.
    let pinned = ironauth_saml::x509::pinned(&certificate_der(&document))
        .expect("the published certificate is readable");

    // AND A REAL REQUEST, signed by the endpoint, verified against it.
    let (status, headers, body) = get(&harness, &wired.start_path).await;
    assert_eq!(status, 303, "{body}");
    let location = headers
        .get(axum::http::header::LOCATION)
        .expect("a redirect")
        .to_str()
        .expect("ascii")
        .to_owned();
    let (_, query) = location.split_once('?').expect("a query");
    let saml_request = param(query, "SAMLRequest").expect("SAMLRequest");
    let sig_alg = param(query, "SigAlg").expect("SigAlg");
    let signature = base64::engine::general_purpose::STANDARD
        .decode(percent_decode(
            &param(query, "Signature").expect("Signature"),
        ))
        .expect("base64");
    let signing_input = format!("SAMLRequest={saml_request}&SigAlg={sig_alg}");

    let ironauth_jose::xmldsig::XmlSigKey::Rsa { modulus, exponent } = &pinned.key else {
        panic!("the published key is not RSA: {:?}", pinned.key);
    };
    let trusted = ironauth_jose::TrustedKey::rsa(None, modulus, exponent).expect("a trusted key");
    ironauth_jose::verify_detached(
        &trusted,
        ironauth_jose::JwsAlgorithm::Rs256,
        signing_input.as_bytes(),
        &signature,
    )
    .expect("the published certificate does not verify a request this deployment signed");
}

#[tokio::test]
async fn each_connection_publishes_its_own_key_and_not_another() {
    // PER CONNECTION, like the key itself. Two connections, two documents: each must carry its
    // OWN certificate, and a build selecting by scope rather than by connection would serve one
    // document for both -- so every request from one of them would fail verification at a
    // provider that had uploaded the other's.
    let harness = Harness::start_store_backed().await;
    let first = wire(&harness, true).await;
    let second = wire(&harness, true).await;

    let mut certificates = Vec::new();
    for wired in [&first, &second] {
        let path = format!(
            "/t/{}/e/{}/saml/metadata/{}",
            harness.scope().tenant(),
            harness.scope().environment(),
            wired.connection
        );
        let (status, _, document) = get(&harness, &path).await;
        assert_eq!(status, 200, "{document}");
        assert!(
            document.contains(&format!("entityID=\"{}\"", wired.audience)),
            "a connection's document carried another's entity id: {document}"
        );
        certificates.push(certificate_der(&document));
    }
    assert_ne!(
        certificates[0], certificates[1],
        "two connections published the same certificate"
    );
}

#[tokio::test]
async fn the_validity_window_is_anchored_to_the_key_and_not_to_the_request() {
    // A DOCUMENT THAT CHANGED ON EVERY FETCH would look to an identity provider like a rotation
    // that never happened, and two operators fetching on different days would upload different
    // certificates for one key.
    //
    // TWO FETCHES BEING EQUAL DOES NOT PROVE THAT, and an earlier version of this test asserted
    // only that. The harness clock is frozen, so a window anchored to the REQUEST is also
    // identical across two fetches -- the test passed against the defect it was written to
    // catch. What separates the two anchors is a key whose creation instant is not the request
    // instant, so this backdates the key by thirty days and reads the window back out of the
    // published certificate with the pinning parser.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, false).await;
    let thirty_days_micros: i64 = 30 * 24 * 60 * 60 * 1_000_000;
    let created_at = now_micros(harness.env()) - thirty_days_micros;
    provision_key_at(&harness, &wired.connection, created_at).await;

    let path = format!(
        "/t/{}/e/{}/saml/metadata/{}",
        harness.scope().tenant(),
        harness.scope().environment(),
        wired.connection
    );

    let (status, _, first) = get(&harness, &path).await;
    assert_eq!(status, 200, "{first}");
    let pinned = ironauth_saml::x509::pinned(&certificate_der(&first))
        .expect("the published certificate is readable");

    // THE KEY'S INSTANT, TO THE SECOND -- not the request's, which is thirty days later.
    assert_eq!(
        pinned.not_before_unix_secs,
        created_at / 1_000_000,
        "the validity window is not anchored to the key's creation instant"
    );
    assert_ne!(
        pinned.not_before_unix_secs,
        now_micros(harness.env()) / 1_000_000,
        "the validity window is anchored to the request instant"
    );
    // AND FIVE YEARS WIDE from there, which is the constant the route documents.
    assert_eq!(
        pinned.not_after_unix_secs - pinned.not_before_unix_secs,
        5 * 365 * 24 * 60 * 60
    );

    // AND STABLE, which is what the anchoring buys.
    let (_, _, second) = get(&harness, &path).await;
    assert_eq!(
        first, second,
        "the metadata document is not stable across fetches"
    );
}

#[tokio::test]
async fn the_document_is_cacheable_and_every_refusal_is_not() {
    // THE ROUTE'S DOC ARGUES A SPECIFIC max-age AND NOTHING MEASURED IT. A metadata document an
    // identity provider re-signs on every poll is the cost this header exists to avoid, and a
    // REFUSAL that got cached would outlive the thing it refused -- an operator who provisions a
    // key would keep being told there is none.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, true).await;
    let base = format!(
        "/t/{}/e/{}/saml/metadata",
        harness.scope().tenant(),
        harness.scope().environment()
    );

    let (status, headers, body) = get(&harness, &format!("{base}/{}", wired.connection)).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        headers
            .get(axum::http::header::CACHE_CONTROL)
            .map(|value| value.to_str().unwrap_or_default()),
        Some("public, max-age=300"),
        "the published document is not cacheable as the route documents"
    );

    // A CONNECTION WITH NO KEY (409) AND AN UNKNOWN ONE (404), both uncacheable.
    let keyless = wire(&harness, false).await;
    for path in [
        format!("{base}/{}", keyless.connection),
        format!("{base}/not-an-id"),
    ] {
        let (status, headers, body) = get(&harness, &path).await;
        assert!(status.is_client_error(), "{status} {body}");
        assert_eq!(
            headers
                .get(axum::http::header::CACHE_CONTROL)
                .map(|value| value.to_str().unwrap_or_default()),
            Some("no-store"),
            "a refusal at {path} is cacheable"
        );
    }
}

#[tokio::test]
async fn a_refusal_here_does_not_talk_about_signing_in() {
    // THE ROUTE SHARES ITS KEY LOADER WITH THE START ENDPOINT, and an earlier version shared the
    // start endpoint's RENDERED PAGE with it: fetching metadata for a keyless connection
    // answered "Sign-in unavailable" and advised uploading the very document being fetched. The
    // shared step decides which outcome; the sentence belongs to the route.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, false).await;
    let path = format!(
        "/t/{}/e/{}/saml/metadata/{}",
        harness.scope().tenant(),
        harness.scope().environment(),
        wired.connection
    );

    let (status, _, body) = get(&harness, &path).await;
    assert_eq!(status, 409, "{body}");
    assert!(
        !body.contains("Sign-in unavailable"),
        "the metadata route serves the start route's page: {body}"
    );
    assert!(body.contains("no certificate to publish"), "{body}");
}

#[tokio::test]
async fn a_connection_with_no_key_has_no_metadata_to_publish() {
    // THE SAME OUTCOME THE START ROUTE REACHES -- it is the same missing thing and the same next
    // step, provision a key -- but said in this route's own words. A document without a
    // `KeyDescriptor` would be accepted by an identity provider and then verify nothing.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, false).await;
    let path = format!(
        "/t/{}/e/{}/saml/metadata/{}",
        harness.scope().tenant(),
        harness.scope().environment(),
        wired.connection
    );

    let (status, _, body) = get(&harness, &path).await;
    assert_eq!(status, 409, "{body}");
    assert!(body.contains("no signing key"), "{body}");
}

#[tokio::test]
async fn an_unknown_connection_cannot_be_told_from_a_malformed_one_at_the_metadata_url() {
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    let absent = SamlConnectionId::generate(harness.env(), &scope);
    let foreign_scope = ironauth_store::Scope::new(
        ironauth_store::TenantId::generate(harness.env()),
        ironauth_store::EnvironmentId::generate(harness.env()),
    );
    let foreign = SamlConnectionId::generate(harness.env(), &foreign_scope);

    let mut answers = Vec::new();
    for id in [
        absent.to_string(),
        foreign.to_string(),
        "not-an-id".to_owned(),
        "smc_".to_owned(),
    ] {
        let path = format!(
            "/t/{}/e/{}/saml/metadata/{id}",
            scope.tenant(),
            scope.environment()
        );
        let (status, headers, page) = get(&harness, &path).await;
        answers.push((status, header_shape(&headers), page));
    }
    assert_eq!(answers[0].0, 404);
    for answer in &answers[1..] {
        assert_eq!(answer.0, answers[0].0, "the answers differ by status");
        assert_eq!(answer.1, answers[0].1, "the answers differ by header");
        assert_eq!(answer.2, answers[0].2, "the answers differ by body");
    }
}
