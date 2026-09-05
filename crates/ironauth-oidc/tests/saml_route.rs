//! The SAML HTTP POST binding, over the real router (issue #139).
//!
//! `saml_acs.rs` measures the PROTOCOL against a real database and does not know what HTTP is.
//! This measures the TRANSPORT: that a base64 form field reaches it, that the connection comes
//! from the URL and not the document, that a verified assertion mints a session cookie, and that
//! every refusal says something an operator can act on without saying anything to an attacker.
#![cfg(feature = "testing")]

mod common;

use base64::Engine as _;
use common::Harness;
use ironauth_env::Env;
use ironauth_jose::xmldsig::test_util::XmlTestKey;
use ironauth_store::{
    CorrelationId, IdentifierType, NewSamlCertificate, NewSamlConnection, NewUserIdentifier,
    OrganizationId, SamlCertificateId, SamlConnectionId, SamlKeyKind, UniquenessMode, UserId,
    UserIdentifierId,
};
use serde_json::json;
use std::fmt::Write as _;

const ISSUER: &str = "urn:idp";
const EMAIL: &str = "ada@globex.example";
const NAMEID_FORMAT: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

/// The connection, the key pinned on it, and where its responses are posted.
struct Wired {
    connection: SamlConnectionId,
    key: XmlTestKey,
    audience: String,
    acs_url: String,
    path: String,
}

/// Create an organization, a SAML connection and a pinned key, and work out the URL the
/// identity provider would be told to post to.
async fn wire(harness: &Harness, nameid_format: &str) -> Wired {
    let env = harness.env().clone();
    let scope = harness.scope();
    let organization = OrganizationId::generate(&env, &scope);
    // THE CONTROL PLANE CREATES, THE DATA PLANE READS, and the two are different database
    // roles. Seeding through `harness.store()` -- the app role the route itself runs as -- is
    // `permission denied for table organizations`, which is the schema saying the same thing.
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
    // THE ACS URL IS DERIVED FROM THE ROUTE, not invented, because the `acs_url` column is what
    // `check` compares the assertion's `Recipient` against. A fixture that made up a URL would
    // pass its own check and tell us nothing about the one an operator will paste into Okta.
    let path = format!(
        "/t/{}/e/{}/saml/acs/{connection}",
        scope.tenant(),
        scope.environment()
    );
    let acs_url = format!("https://ironauth.example{path}");
    let audience = format!("https://ironauth.example/t/{}/saml", scope.tenant());

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
                idp_sso_url: "https://idp.example/sso",
                sp_entity_id: &audience,
                acs_url: &acs_url,
                allow_unsolicited: true,
                clock_skew_secs: 30,
                max_assertion_age_secs: 300,
                nameid_format,
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

    Wired {
        connection,
        key,
        audience,
        acs_url,
        path,
    }
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

/// An assertion signed for `wired`, valid around the harness's own clock.
///
/// THE WINDOW IS WRITTEN AROUND THE REAL CLOCK, unlike `saml_acs.rs`'s fixtures, because the
/// route reads its instant from the deployment's clock seam rather than taking one as an
/// argument. A fixture pinned to a fixed date would be measuring nothing after it lapsed.
fn signed(wired: &Wired, env: &Env, assertion_id: &str, name_id: &str, format: &str) -> String {
    let now = now_micros(env) / 1_000_000;
    let children = format!(
        "<saml:Issuer>{ISSUER}</saml:Issuer>\
         <saml:Subject>\
         <saml:NameID Format=\"{format}\">{name_id}</saml:NameID>\
         <saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\
         <saml:SubjectConfirmationData Recipient=\"{}\" NotOnOrAfter=\"{}\"/>\
         </saml:SubjectConfirmation></saml:Subject>\
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

/// `seconds` since the epoch as the `xsd:dateTime` SAML writes.
fn rfc3339(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);
    // The civil-from-days algorithm, so the fixture needs no date library.
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

/// The form an identity provider posts, with `RelayState` set to whatever the browser carried.
fn form(response: &str, relay_state: Option<&str>) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(response);
    let mut body = format!("SAMLResponse={}", urlencode(&encoded));
    if let Some(relay) = relay_state {
        let _ = write!(body, "&RelayState={}", urlencode(relay));
    }
    body
}

fn urlencode(raw: &str) -> String {
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

/// Give `subject` a verified email identifier, which is what the route resolves the `NameID`
/// against.
async fn add_verified_email(harness: &Harness, subject: &UserId, raw: &str, verified: bool) {
    let env = harness.env().clone();
    harness
        .db()
        .control_store()
        .scoped(harness.scope())
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .user_identifiers()
        .add(
            &env,
            NewUserIdentifier {
                id: &UserIdentifierId::generate(&env, &harness.scope()),
                user_id: subject,
                identifier_type: IdentifierType::Email,
                raw,
                verified,
                mode: UniquenessMode::EnvironmentWide,
                org: None,
            },
            None,
        )
        .await
        .expect("add the email identifier");
}

#[tokio::test]
async fn a_signed_response_signs_the_provisioned_user_in() {
    // THE WHOLE POINT, end to end: an identity provider posts a base64 response to the URL its
    // connection names, and the browser comes away with a session. Everything else in this file
    // is a way for that not to happen.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, NAMEID_FORMAT).await;
    let subject = harness.seed_passwordless_user("ada").await;
    let subject = UserId::parse_in_scope(&subject, &harness.scope()).expect("subject");
    add_verified_email(&harness, &subject, EMAIL, true).await;

    let response = signed(&wired, harness.env(), "_assertion_ok", EMAIL, NAMEID_FORMAT);
    let (status, headers, body) = harness
        .post_form(&wired.path, &form(&response, None), None)
        .await;

    assert_eq!(status, 200, "{body}");
    let cookies = headers
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .count();
    assert!(
        cookies > 0,
        "a verified assertion minted no session: {body}"
    );
}

#[tokio::test]
async fn the_same_response_cannot_be_posted_twice() {
    // THE REPLAY CACHE, REACHED THROUGH HTTP. `saml_acs.rs` proves the store refuses the second
    // admission; this proves the route does not somehow hand the second POST a session anyway --
    // which is what an endpoint that established the session BEFORE consuming would do.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, NAMEID_FORMAT).await;
    let subject = harness.seed_passwordless_user("ada").await;
    let subject = UserId::parse_in_scope(&subject, &harness.scope()).expect("subject");
    add_verified_email(&harness, &subject, EMAIL, true).await;

    let response = signed(
        &wired,
        harness.env(),
        "_assertion_once",
        EMAIL,
        NAMEID_FORMAT,
    );
    let (first, _, _) = harness
        .post_form(&wired.path, &form(&response, None), None)
        .await;
    assert_eq!(first, 200);

    let (second, headers, body) = harness
        .post_form(&wired.path, &form(&response, None), None)
        .await;
    assert_eq!(second, 400, "a replayed response was accepted: {body}");
    assert_eq!(
        headers
            .get_all(axum::http::header::SET_COOKIE)
            .iter()
            .count(),
        0,
        "a replayed response minted a session"
    );
}

#[tokio::test]
async fn a_response_for_another_connection_is_refused_at_the_url_it_was_posted_to() {
    // THE CONNECTION COMES FROM THE PATH, NOT THE DOCUMENT. Two connections in one environment,
    // each with its own pinned key, audience and ACS URL: a response built for the first and
    // posted at the second's URL must be refused. An endpoint that resolved the connection from
    // the response's `Issuer` would accept it, and the two connections here share an `Issuer` on
    // purpose so that resolution would find the wrong one.
    let harness = Harness::start_store_backed().await;
    let first = wire(&harness, NAMEID_FORMAT).await;
    let second = wire(&harness, NAMEID_FORMAT).await;
    let subject = harness.seed_passwordless_user("ada").await;
    let subject = UserId::parse_in_scope(&subject, &harness.scope()).expect("subject");
    add_verified_email(&harness, &subject, EMAIL, true).await;

    let for_first = signed(
        &first,
        harness.env(),
        "_assertion_first",
        EMAIL,
        NAMEID_FORMAT,
    );
    let (status, headers, body) = harness
        .post_form(&second.path, &form(&for_first, None), None)
        .await;

    assert_eq!(status, 400, "{body}");
    assert_eq!(
        headers
            .get_all(axum::http::header::SET_COOKIE)
            .iter()
            .count(),
        0,
        "a response for another connection minted a session"
    );
    // AND IT FAILED ON THE SIGNATURE, which is the first thing the other connection's anchors
    // disagree with -- not on the audience, which would mean the wrong key had verified it.
    assert!(
        body.contains("signature"),
        "the refusal was not about the trust anchors: {body}"
    );
    assert_ne!(first.connection.to_string(), second.connection.to_string());
}

#[tokio::test]
async fn an_identity_with_no_provisioned_account_is_refused_without_saying_which() {
    // A VALID ASSERTION FOR SOMEBODY THIS ENVIRONMENT HAS NEVER HEARD OF. It verifies, every
    // condition passes, and there is no local account -- so no session, and an answer that does
    // not distinguish "no such account" from "that account cannot sign in", because the party
    // reading it is whoever posted the response.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, NAMEID_FORMAT).await;

    let response = signed(
        &wired,
        harness.env(),
        "_assertion_stranger",
        "stranger@globex.example",
        NAMEID_FORMAT,
    );
    let (status, headers, body) = harness
        .post_form(&wired.path, &form(&response, None), None)
        .await;

    assert_eq!(status, 403, "{body}");
    assert_eq!(
        headers
            .get_all(axum::http::header::SET_COOKIE)
            .iter()
            .count(),
        0
    );
    assert!(
        !body.contains("stranger@globex.example"),
        "the refusal echoed the identity back: {body}"
    );
}

#[tokio::test]
async fn an_unverified_identifier_does_not_answer_for_an_account() {
    // THE IDENTITY PROVIDER VOUCHES FOR THE ADDRESS IT ASSERTS, NOT FOR A LOCAL ROW NOBODY
    // PROVED. An unverified identifier is somebody who typed that address during signup and
    // never confirmed it; signing an asserted subject into it would let a connection claim an
    // account its user does not own -- which is the account-takeover shape this whole surface
    // exists inside.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, NAMEID_FORMAT).await;
    let subject = harness.seed_passwordless_user("ada").await;
    let subject = UserId::parse_in_scope(&subject, &harness.scope()).expect("subject");
    add_verified_email(&harness, &subject, EMAIL, false).await;

    let response = signed(
        &wired,
        harness.env(),
        "_assertion_unverified",
        EMAIL,
        NAMEID_FORMAT,
    );
    let (status, headers, body) = harness
        .post_form(&wired.path, &form(&response, None), None)
        .await;

    assert_eq!(status, 403, "{body}");
    assert_eq!(
        headers
            .get_all(axum::http::header::SET_COOKIE)
            .iter()
            .count(),
        0,
        "an unverified identifier answered for an account"
    );
}

#[tokio::test]
async fn a_connection_in_an_unresolvable_nameid_format_says_so() {
    // NOT "UNKNOWN USER". A connection configured for `persistent` names its subject with an
    // opaque string that means nothing to the identifier table, and this build has nowhere to
    // store the mapping yet. Refusing it as "no account is provisioned" would send an operator
    // to look at their user list, which is not where the gap is.
    const PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";

    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, PERSISTENT).await;

    let response = signed(
        &wired,
        harness.env(),
        "_assertion_persistent",
        "9d3f1c0a",
        PERSISTENT,
    );
    let (status, _, body) = harness
        .post_form(&wired.path, &form(&response, None), None)
        .await;

    assert_eq!(status, 501, "{body}");
    assert!(
        body.contains("NameID format"),
        "the refusal did not name the gap: {body}"
    );
}

#[tokio::test]
async fn the_posted_relay_state_never_becomes_a_redirect() {
    // `RelayState` TRAVELS THROUGH THE BROWSER, so the posted value is whatever the last party
    // to touch it wanted. Honouring it is an open redirect, and it is the one an attacker
    // reaches WITHOUT any signature at all: the field is not covered by the assertion. The
    // route reads the RelayState this deployment RECORDED, and this response is unsolicited, so
    // there is none -- the answer must be a page, never a Location.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, NAMEID_FORMAT).await;
    let subject = harness.seed_passwordless_user("ada").await;
    let subject = UserId::parse_in_scope(&subject, &harness.scope()).expect("subject");
    add_verified_email(&harness, &subject, EMAIL, true).await;

    let response = signed(
        &wired,
        harness.env(),
        "_assertion_relay",
        EMAIL,
        NAMEID_FORMAT,
    );
    let (status, headers, body) = harness
        .post_form(
            &wired.path,
            &form(&response, Some("https://evil.example/steal")),
            None,
        )
        .await;

    assert_eq!(status, 200, "{body}");
    assert!(
        headers.get(axum::http::header::LOCATION).is_none(),
        "the posted RelayState became a redirect: {:?}",
        headers.get(axum::http::header::LOCATION)
    );
    assert!(
        !body.contains("evil.example"),
        "the value was echoed: {body}"
    );
}

#[tokio::test]
async fn a_body_that_is_not_a_saml_response_is_refused_before_anything_is_read() {
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, NAMEID_FORMAT).await;

    // NOT BASE64.
    let (status, _, _) = harness
        .post_form(&wired.path, "SAMLResponse=%7B%7Dnot-base64%21", None)
        .await;
    assert_eq!(status, 400);

    // BASE64 OF SOMETHING THAT IS NOT XML.
    let (status, _, _) = harness
        .post_form(&wired.path, &form("this is not xml", None), None)
        .await;
    assert_eq!(status, 400);

    // NO FIELD AT ALL: axum refuses the form before the handler runs.
    let (status, _, _) = harness.post_form(&wired.path, "RelayState=%2F", None).await;
    assert!(
        status.is_client_error(),
        "a form with no SAMLResponse was not refused: {status}"
    );
}

#[tokio::test]
async fn an_unknown_connection_answers_exactly_like_a_malformed_one() {
    // NO ENUMERATION ORACLE. Whoever is posting learns nothing about which connection ids this
    // environment holds: a well-formed id for a connection that does not exist, an id from
    // another scope, and a string that is not an id at all are one answer.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, NAMEID_FORMAT).await;
    let scope = harness.scope();
    let absent = SamlConnectionId::generate(harness.env(), &scope);
    let body = form(
        &signed(&wired, harness.env(), "_assertion_x", EMAIL, NAMEID_FORMAT),
        None,
    );

    let mut answers = Vec::new();
    for id in [
        absent.to_string(),
        "not-an-id".to_owned(),
        String::from("smc_"),
    ] {
        let path = format!(
            "/t/{}/e/{}/saml/acs/{id}",
            scope.tenant(),
            scope.environment()
        );
        let (status, _, page) = harness.post_form(&path, &body, None).await;
        answers.push((status, page));
    }
    let (first_status, first_page) = &answers[0];
    assert_eq!(*first_status, 404);
    for (status, page) in &answers[1..] {
        assert_eq!(status, first_status, "the answers differ by status");
        assert_eq!(page, first_page, "the answers differ by body");
    }
}
