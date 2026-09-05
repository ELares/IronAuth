//! Starting a SAML sign-in over the real router (issue #139).
//!
//! # The loop this closes
//!
//! Before this endpoint the assertion consumer service could only be reached IdP-initiated:
//! nothing issued an `AuthnRequest`, so no outstanding request existed, so a response naming one
//! was always `UnknownRequest` and only `allow_unsolicited = true` could get anywhere. The
//! headline test here drives BOTH halves in one go -- start a flow, then answer it at the ACS on
//! a connection that refuses unsolicited responses -- which is the first time the strong defence
//! #139 requires is exercised end to end.
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
const SUBJECT: &str = "ada@globex.example";
const NAMEID_FORMAT: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

struct Wired {
    connection: SamlConnectionId,
    sso_url: String,
    key: XmlTestKey,
    audience: String,
    acs_url: String,
    acs_path: String,
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
    let sso_url = idp_sso_url.to_owned();
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
        sso_url,
        key,
        audience,
        acs_url,
        acs_path,
        start_path,
    }
}

/// Mint the SP signing key the connection needs to start a flow.
///
/// SPLIT OUT OF `wire` because it is the one thing a test varies, and because #140 will replace
/// this call with an admin endpoint: keeping it in one place is what makes that a one-line
/// change rather than a hunt.
async fn provision_key(harness: &Harness, connection: &SamlConnectionId) {
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
                created_at_unix_micros: now_micros(&env),
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

/// A response answering `in_response_to`, signed by the connection's pinned key.
fn signed(wired: &Wired, env: &Env, assertion_id: &str, in_response_to: &str) -> String {
    let now = now_micros(env) / 1_000_000;
    let children = format!(
        "<saml:Issuer>{ISSUER}</saml:Issuer>\
         <saml:Subject>\
         <saml:NameID Format=\"{NAMEID_FORMAT}\">{SUBJECT}</saml:NameID>\
         <saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\
         <saml:SubjectConfirmationData InResponseTo=\"{in_response_to}\" Recipient=\"{}\" \
         NotOnOrAfter=\"{}\"/></saml:SubjectConfirmation></saml:Subject>\
         <saml:Conditions NotBefore=\"{}\" NotOnOrAfter=\"{}\">\
         <saml:AudienceRestriction><saml:Audience>{}</saml:Audience>\
         </saml:AudienceRestriction></saml:Conditions>\
         <saml:AttributeStatement/>",
        wired.acs_url,
        rfc3339(now + 120),
        rfc3339(now - 120),
        rfc3339(now + 120),
        wired.audience,
    );
    ironauth_saml::test_util::signed_response_with(&wired.key, assertion_id, &children)
}

fn rfc3339(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        (rest % 3600) / 60,
        rest % 60
    )
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

/// Inflate the stored-block DEFLATE stream the redirect binding carries.
fn inflate_stored(raw: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut index = 0;
    loop {
        let header = *raw.get(index)?;
        if header & 0b0000_0110 != 0 {
            return None;
        }
        let last = header & 1 == 1;
        let len = u16::from_le_bytes([*raw.get(index + 1)?, *raw.get(index + 2)?]);
        let start = index + 5;
        let end = start + len as usize;
        out.extend_from_slice(raw.get(start..end)?);
        index = end;
        if last {
            return Some(out);
        }
    }
}

/// The `AuthnRequest` XML out of a `Location` header.
fn request_xml(location: &str) -> String {
    let (_, query) = location.split_once('?').expect("a query");
    let encoded = param(query, "SAMLRequest").expect("SAMLRequest");
    let deflated = base64::engine::general_purpose::STANDARD
        .decode(percent_decode(&encoded))
        .expect("standard base64");
    String::from_utf8(inflate_stored(&deflated).expect("a stored-block stream")).expect("utf-8")
}

#[tokio::test]
async fn a_started_flow_is_answerable_at_the_acs_that_refuses_unsolicited_responses() {
    // THE LOOP, AND THE REASON THIS ENDPOINT EXISTS. The connection has `allow_unsolicited =
    // false`, so before this PR every response it could receive was refused: one naming a
    // request hit `UnknownRequest` because nothing issued requests, and one naming none hit
    // `UnsolicitedRefused`. Starting a flow writes the outstanding request that makes the strong
    // defence reachable, and this drives both halves against the same connection.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, true).await;

    let (status, headers, body) = get(&harness, &wired.start_path).await;
    assert_eq!(status, 303, "{body}");
    let location = headers
        .get(axum::http::header::LOCATION)
        .expect("a redirect to the identity provider")
        .to_str()
        .expect("ascii");
    assert!(
        location.starts_with("https://idp.example/sso?"),
        "{location}"
    );

    // THE REQUEST ID COMES OUT OF THE DOCUMENT THIS DEPLOYMENT JUST SENT, not out of a fixture:
    // what is being measured is that the id the identity provider will echo is the id that was
    // recorded, and inventing one here would measure neither.
    let xml = request_xml(location);
    let id = xml
        .split("ID=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("the request carries an ID")
        .to_owned();

    let response = signed(&wired, harness.env(), "_assertion_looped", &id);
    let encoded = base64::engine::general_purpose::STANDARD.encode(&response);
    let (status, _, body) = harness
        .post_form(
            &wired.acs_path,
            &format!("SAMLResponse={}", urlencode(&encoded)),
            None,
        )
        .await;
    assert_eq!(
        status, 200,
        "a response answering a request this deployment issued was refused: {body}"
    );

    // AND THE REQUEST IS SPENT: the same response replayed is refused, which is what "exactly
    // once" means and what a request row that was never written could not provide.
    let (status, _, body) = harness
        .post_form(
            &wired.acs_path,
            &format!("SAMLResponse={}", urlencode(&encoded)),
            None,
        )
        .await;
    assert_eq!(
        status, 400,
        "the outstanding request was spendable twice: {body}"
    );
}

#[tokio::test]
async fn the_request_is_signed_with_the_connections_own_key() {
    // SIGNED BY DEFAULT, with no switch. The signature is over the octet string OASIS Bindings
    // 3.4.4.1 names, and `ironauth-saml`'s own suite proves that shape; what this adds is that
    // the key doing the signing is the one PROVISIONED FOR THIS CONNECTION and read from the
    // row, rather than any key the endpoint happened to have.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, true).await;

    let (status, headers, body) = get(&harness, &wired.start_path).await;
    assert_eq!(status, 303, "{body}");
    let location = headers
        .get(axum::http::header::LOCATION)
        .expect("a redirect")
        .to_str()
        .expect("ascii");
    let (_, query) = location.split_once('?').expect("a query");

    let signature = param(query, "Signature").expect("the request is signed");
    let sig_alg = param(query, "SigAlg").expect("SigAlg");
    assert_eq!(
        String::from_utf8(percent_decode(&sig_alg)).expect("utf-8"),
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    );

    let stored = harness
        .store()
        .scoped(harness.scope())
        .saml_connections()
        .active_sp_key(&wired.connection)
        .await
        .expect("read the key")
        .expect("the connection has a key");
    let key = ironauth_jose::SigningKey::rsa_from_pkcs1_der(
        None,
        ironauth_jose::JwsAlgorithm::Rs256,
        stored.material.expose(),
    )
    .expect("load the stored key");

    let saml_request = param(query, "SAMLRequest").expect("SAMLRequest");
    let signing_input = format!("SAMLRequest={saml_request}&SigAlg={sig_alg}");
    ironauth_jose::verify_detached(
        &key.verifying_key().expect("verifying key"),
        ironauth_jose::JwsAlgorithm::Rs256,
        signing_input.as_bytes(),
        &base64::engine::general_purpose::STANDARD
            .decode(percent_decode(&signature))
            .expect("base64"),
    )
    .expect("the request was not signed by the key stored for this connection");
}

#[tokio::test]
async fn a_connection_with_no_signing_key_cannot_start_a_flow() {
    // ENFORCEMENT NEEDS A GRANTING PATH, and the refusal names the one it needs: provisioning a
    // key. Falling back to an unsigned request would be a weaker default than #139 asks for,
    // arrived at silently, on a connection whose operator never chose it.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, false).await;

    let (status, headers, body) = get(&harness, &wired.start_path).await;
    assert_eq!(status, 409, "{body}");
    assert!(headers.get(axum::http::header::LOCATION).is_none());
    assert!(body.contains("no signing key"), "{body}");
}

#[tokio::test]
async fn the_request_names_the_connections_own_values_and_is_recorded_before_the_redirect() {
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, true).await;

    let (status, headers, _) = get(&harness, &wired.start_path).await;
    assert_eq!(status, 303);
    let location = headers
        .get(axum::http::header::LOCATION)
        .expect("a redirect")
        .to_str()
        .expect("ascii")
        .to_owned();
    let xml = request_xml(&location);

    // FROM THE ROW, not from a constant this endpoint carries: the audience and the ACS URL are
    // per connection, and a build that baked either in would send every customer's identity
    // provider the same one.
    assert!(
        xml.contains(&format!("<saml:Issuer>{}</saml:Issuer>", wired.audience)),
        "{xml}"
    );
    assert!(
        xml.contains(&format!(
            "AssertionConsumerServiceURL=\"{}\"",
            wired.acs_url
        )),
        "{xml}"
    );
    assert!(
        xml.contains("Destination=\"https://idp.example/sso\""),
        "{xml}"
    );

    // AND IT WAS RECORDED BEFORE THE BROWSER WAS SENT. The witness is that the row can be spent:
    // a request written after the redirect would be a race a real identity provider wins.
    let id = xml
        .split("ID=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("an ID")
        .to_owned();
    let spent = harness
        .store()
        .scoped(harness.scope())
        .saml_replay()
        .consume_request(&wired.connection, &id, now_micros(harness.env()))
        .await;
    assert!(
        spent.is_ok(),
        "the request the browser was sent with was never recorded: {spent:?}"
    );
}

#[tokio::test]
async fn an_unknown_connection_cannot_be_told_from_a_malformed_one() {
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    let absent = SamlConnectionId::generate(harness.env(), &scope);

    let mut answers = Vec::new();
    for id in [
        absent.to_string(),
        "not-an-id".to_owned(),
        "smc_".to_owned(),
    ] {
        let path = format!(
            "/t/{}/e/{}/saml/start/{id}",
            scope.tenant(),
            scope.environment()
        );
        let (status, _, page) = get(&harness, &path).await;
        answers.push((status, page));
    }
    assert_eq!(answers[0].0, 404);
    for answer in &answers[1..] {
        assert_eq!(answer.0, answers[0].0, "the answers differ by status");
        assert_eq!(answer.1, answers[0].1, "the answers differ by body");
    }
}

fn urlencode(raw: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    out
}

#[tokio::test]
async fn each_connection_signs_with_its_own_key_and_not_another() {
    // PER-CONNECTION, MEASURED. The earlier test verified the signature against the key it read
    // back from the row, which a build selecting ANY key in the environment would also pass --
    // there was only ever one. Two connections, each with its own key: each request must verify
    // under its OWN connection's key and NOT under the other's.
    let harness = Harness::start_store_backed().await;
    let first = wire(&harness, true).await;
    let second = wire(&harness, true).await;

    let (status, headers, body) = get(&harness, &first.start_path).await;
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

    let own = loaded_key(&harness, &first.connection).await;
    ironauth_jose::verify_detached(
        &own.verifying_key().expect("verifying key"),
        ironauth_jose::JwsAlgorithm::Rs256,
        signing_input.as_bytes(),
        &signature,
    )
    .expect("the request did not verify under its own connection's key");

    let other = loaded_key(&harness, &second.connection).await;
    assert!(
        ironauth_jose::verify_detached(
            &other.verifying_key().expect("verifying key"),
            ironauth_jose::JwsAlgorithm::Rs256,
            signing_input.as_bytes(),
            &signature,
        )
        .is_err(),
        "one connection's request verified under another connection's key"
    );
}

#[tokio::test]
async fn the_recorded_return_to_is_the_validated_one_and_is_bounded() {
    // TWO DEFECTS IN ONE LINE, both unmeasured. `parse_resume` TRIMS before it checks, so a
    // value wrapped in whitespace passed the check while the UNTRIMMED string was recorded --
    // validating one string and using another. And a value over migration 0198's 1024-byte
    // column bound passed the check and then failed the INSERT, which an unauthenticated caller
    // could trigger at will for a 500.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, true).await;

    // WRAPPED IN WHITESPACE: accepted, and what lands in the row is the trimmed value.
    // THE HARNESS'S REAL CLIENT ID, because `parse_resume` parses it as a SCOPED identifier: an
    // invented `cli_recorded` is refused outright, and a first version of this test used one --
    // so it read back `None` for a value that had never been accepted at all, and would have
    // passed against a build that recorded the untrimmed string.
    let resume = format!("/authorize?client_id={}&scope=openid", harness.client_id());
    let (status, headers, body) = get(
        &harness,
        &format!(
            "{}?return_to={}",
            wired.start_path,
            urlencode(&format!("  {resume}  "))
        ),
    )
    .await;
    assert_eq!(status, 303, "{body}");
    let location = headers
        .get(axum::http::header::LOCATION)
        .expect("a redirect")
        .to_str()
        .expect("ascii")
        .to_owned();
    let recorded = spend_at(&harness, &wired, &location).await;
    assert_eq!(
        recorded.as_deref(),
        Some(resume.as_str()),
        "the untrimmed value was recorded"
    );

    // OVER THE COLUMN'S BOUND: refused as a return location rather than answering 500. The path
    // parses -- it is a valid resume with a very long scope -- so only the length bound can
    // refuse it.
    let long = format!(
        "/authorize?client_id={}&scope={}",
        harness.client_id(),
        "a".repeat(1200)
    );
    assert!(
        long.len() > 1024,
        "the over-long fixture must exceed migration 0198's relay_state bound"
    );
    let (status, headers, body) = get(
        &harness,
        &format!("{}?return_to={}", wired.start_path, urlencode(&long)),
    )
    .await;
    assert_eq!(
        status, 303,
        "an over-long return_to was a caller-triggered fault: {body}"
    );
    let location = headers
        .get(axum::http::header::LOCATION)
        .expect("a redirect")
        .to_str()
        .expect("ascii")
        .to_owned();
    assert_eq!(
        spend_at(&harness, &wired, &location).await,
        None,
        "an over-long return_to was recorded anyway"
    );
}

/// The signing key stored for `connection`, loaded.
async fn loaded_key(harness: &Harness, connection: &SamlConnectionId) -> ironauth_jose::SigningKey {
    let stored = harness
        .store()
        .scoped(harness.scope())
        .saml_connections()
        .active_sp_key(connection)
        .await
        .expect("read the key")
        .expect("the connection has a key");
    ironauth_jose::SigningKey::rsa_from_pkcs1_der(
        None,
        ironauth_jose::JwsAlgorithm::Rs256,
        stored.material.expose(),
    )
    .expect("load the stored key")
}

/// Spend the request named by `location` and return the `RelayState` it recorded.
///
/// READ BY SPENDING, because that is the only reader the store exposes -- and it is the path the
/// ACS takes, so what this observes is what a real sign-in would.
///
/// THE LOCATION IS PASSED IN, not re-derived. A first version called the endpoint again to get
/// one, which starts a SECOND flow and spends THAT request -- so it read back the `RelayState` of
/// a request the test never made, and reported `None` for a value that had been recorded
/// correctly. The test failed for a reason that was entirely its own.
async fn spend_at(harness: &Harness, wired: &Wired, location: &str) -> Option<String> {
    let xml = request_xml(location);
    let id = xml
        .split("ID=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("an ID")
        .to_owned();
    harness
        .store()
        .scoped(harness.scope())
        .saml_replay()
        .consume_request(&wired.connection, &id, now_micros(harness.env()))
        .await
        .expect("the request was recorded")
}

#[tokio::test]
async fn a_resume_belonging_to_another_scope_is_not_recorded() {
    // THE HALF ROUND 1 DROPPED. Reaching into `ResumeTarget` for `return_to` also put its `scope`
    // in hand, and discarding it left a PATH-SCOPED route admitting another tenant's authorization
    // path: `parse_resume` recovers the scope by decoding the client id's bytes, with no existence
    // check and no idea which route called it, so every well-formed `cli_` from every tenant
    // parses. This deployment's own row would then hold a return location belonging to somebody
    // else, and the sentence promising a value that could never be honoured is never written
    // would be false.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, true).await;

    let foreign_scope = ironauth_store::Scope::new(
        ironauth_store::TenantId::generate(harness.env()),
        ironauth_store::EnvironmentId::generate(harness.env()),
    );
    let foreign_client = ironauth_store::ClientId::generate(harness.env(), &foreign_scope);
    let foreign = format!("/authorize?client_id={foreign_client}&scope=openid");

    let (status, headers, body) = get(
        &harness,
        &format!("{}?return_to={}", wired.start_path, urlencode(&foreign)),
    )
    .await;
    // THE FLOW STILL STARTS: a return location this route cannot honour is dropped, not a reason
    // to refuse a sign-in the operator asked for. What must not happen is RECORDING it.
    assert_eq!(status, 303, "{body}");
    let location = headers
        .get(axum::http::header::LOCATION)
        .expect("a redirect")
        .to_str()
        .expect("ascii")
        .to_owned();
    assert_eq!(
        spend_at(&harness, &wired, &location).await,
        None,
        "another scope's authorization path was recorded as this connection's return location"
    );

    // AND THIS ROUTE'S OWN SCOPE IS STILL ACCEPTED, so the comparison is not refusing everything.
    let own = format!("/authorize?client_id={}&scope=openid", harness.client_id());
    let (status, headers, body) = get(
        &harness,
        &format!("{}?return_to={}", wired.start_path, urlencode(&own)),
    )
    .await;
    assert_eq!(status, 303, "{body}");
    let location = headers
        .get(axum::http::header::LOCATION)
        .expect("a redirect")
        .to_str()
        .expect("ascii")
        .to_owned();
    assert_eq!(
        spend_at(&harness, &wired, &location).await.as_deref(),
        Some(own.as_str())
    );
}

#[tokio::test]
async fn nothing_that_is_not_a_resume_path_is_recorded() {
    // THE OPEN-REDIRECT DEFENCE ITSELF, which nothing measured: replacing `parse_resume` with a
    // bare trim would have left every test green. Each of these is a value somebody would try,
    // and none may reach the row that the sign-in work will build a `Location` from.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, true).await;

    for hostile in [
        "https://evil.example/steal",
        "//evil.example/steal",
        "/authorize?client_id=not-a-client-id",
        "/dashboard",
        "javascript:alert(1)",
        "/authorize",
    ] {
        let (status, headers, body) = get(
            &harness,
            &format!("{}?return_to={}", wired.start_path, urlencode(hostile)),
        )
        .await;
        assert_eq!(status, 303, "{hostile}: {body}");
        let location = headers
            .get(axum::http::header::LOCATION)
            .expect("a redirect")
            .to_str()
            .expect("ascii")
            .to_owned();
        assert_eq!(
            spend_at(&harness, &wired, &location).await,
            None,
            "{hostile} was recorded as a return location"
        );
    }
}

#[tokio::test]
async fn no_relay_state_reaches_the_identity_provider() {
    // THE THIRD HEADLINE CHANGE OF THE PREVIOUS ROUND, measured by nothing. Every value this
    // endpoint could send exceeds OASIS Bindings 3.4.3's 80-byte cap, so it sends none -- and
    // that is only true while nothing puts one back. A `RelayState` on the wire would also hand
    // the identity provider a return path that is this deployment's business.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, true).await;
    let resume = format!("/authorize?client_id={}&scope=openid", harness.client_id());

    let (status, headers, body) = get(
        &harness,
        &format!("{}?return_to={}", wired.start_path, urlencode(&resume)),
    )
    .await;
    assert_eq!(status, 303, "{body}");
    let location = headers
        .get(axum::http::header::LOCATION)
        .expect("a redirect")
        .to_str()
        .expect("ascii")
        .to_owned();
    let (_, query) = location.split_once('?').expect("a query");

    assert!(
        param(query, "RelayState").is_none(),
        "a RelayState was sent: {location}"
    );
    assert!(
        !location.contains(harness.client_id().to_string().as_str()),
        "the return location reached the identity provider by another name: {location}"
    );

    // AND IT IS RECORDED, which is what makes sending it unnecessary rather than a loss.
    assert_eq!(
        spend_at(&harness, &wired, &location).await.as_deref(),
        Some(resume.as_str())
    );
}

#[tokio::test]
async fn an_sso_url_that_already_has_a_query_gets_an_ampersand() {
    // EVERY FIXTURE IN THIS FILE USED A QUERY-FREE SSO URL, so the `&` arm was dead and
    // collapsing the branch to a bare `?` passed the whole suite -- while breaking every sign-in
    // on the connections the comment names. ADFS deployments commonly carry a query
    // (`?wa=wsignin1.0`), and appending `?` to one that does produces a URL the identity
    // provider reads as one malformed parameter.
    let harness = Harness::start_store_backed().await;
    let adfs = wire_at(
        &harness,
        true,
        "https://adfs.example/adfs/ls/?wa=wsignin1.0",
    )
    .await;

    let (status, headers, body) = get(&harness, &adfs.start_path).await;
    assert_eq!(status, 303, "{body}");
    let location = headers
        .get(axum::http::header::LOCATION)
        .expect("a redirect")
        .to_str()
        .expect("ascii")
        .to_owned();
    assert!(
        location.starts_with("https://adfs.example/adfs/ls/?wa=wsignin1.0&SAMLRequest="),
        "the request was appended with the wrong separator: {location}"
    );
    // AND THE PROVIDER'S OWN PARAMETER SURVIVES, which is what the separator is protecting.
    let (_, query) = location.split_once('?').expect("a query");
    assert_eq!(param(query, "wa").as_deref(), Some("wsignin1.0"));
    assert!(param(query, "SAMLRequest").is_some());
    assert_eq!(adfs.sso_url, "https://adfs.example/adfs/ls/?wa=wsignin1.0");
}

#[tokio::test]
async fn the_request_expires_at_the_window_the_endpoint_documents() {
    // THE FIVE-MINUTE WINDOW, which the constant's doc calls a security bound -- "a longer window
    // here is a longer window there" -- and which nothing asserted: a ten-year TTL passed every
    // test. The store measures that `consume_request` HONOURS an expiry; what was unmeasured is
    // the value this endpoint writes.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, true).await;

    let (status, headers, body) = get(&harness, &wired.start_path).await;
    assert_eq!(status, 303, "{body}");
    let location = headers
        .get(axum::http::header::LOCATION)
        .expect("a redirect")
        .to_str()
        .expect("ascii")
        .to_owned();
    let id = request_id(&location);
    let issued = now_micros(harness.env());
    let replay = harness.store().scoped(harness.scope()).saml_replay();

    // ONE SECOND PAST FIVE MINUTES: gone. The store's predicate is `expires_at > now`, so this
    // reads back the value the endpoint chose rather than the one the test supplies.
    assert!(
        matches!(
            replay
                .consume_request(&wired.connection, &id, issued + 301 * 1_000_000)
                .await,
            Err(ironauth_store::StoreError::NotFound)
        ),
        "the request outlived the documented five-minute window"
    );

    // AND A SECOND INSIDE IT IS STILL THERE, on a fresh request, so the bound is the window and
    // not a request that was never answerable.
    let (_, headers, _) = get(&harness, &wired.start_path).await;
    let location = headers
        .get(axum::http::header::LOCATION)
        .expect("a redirect")
        .to_str()
        .expect("ascii")
        .to_owned();
    let id = request_id(&location);
    assert!(
        replay
            .consume_request(&wired.connection, &id, issued + 299 * 1_000_000)
            .await
            .is_ok(),
        "the request expired before the documented window"
    );
}

/// The `AuthnRequest` ID carried by the request in `location`.
fn request_id(location: &str) -> String {
    request_xml(location)
        .split("ID=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("the request carries an ID")
        .to_owned()
}
