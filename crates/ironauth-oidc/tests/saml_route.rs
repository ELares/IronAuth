//! The SAML HTTP POST binding, over the real router (issue #139).
//!
//! `saml_acs.rs` measures the PROTOCOL against a real database and does not know what HTTP is.
//! This measures the TRANSPORT: that a base64 form field reaches it, that the connection comes
//! from the URL and not the document, that the body gates run before the store is addressed, and
//! that every refusal answers the same way for every input class an enumerator can vary.
//!
//! AND THAT NOTHING IS AUTHENTICATED. An earlier version of this sentence said the suite proved
//! "a verified assertion mints a session cookie", which the endpoint deliberately no longer does
//! -- see the module doc for the four reasons. The assertion is now the other way round, so
//! adding sign-in has to come through here and say so.
#![cfg(feature = "testing")]

mod common;

use base64::Engine as _;
use common::Harness;
use ironauth_env::Env;
use ironauth_jose::xmldsig::test_util::XmlTestKey;
use ironauth_store::{
    CorrelationId, NewSamlCertificate, NewSamlConnection, OrganizationId, SamlCertificateId,
    SamlConnectionId, SamlKeyKind,
};
use serde_json::json;
use std::fmt::Write as _;

const ISSUER: &str = "urn:idp";
const SUBJECT: &str = "ada@globex.example";
const NAMEID_FORMAT: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

/// The connection, the key pinned on it, and where its responses are posted.
struct Wired {
    connection: SamlConnectionId,
    issuer: String,
    key: XmlTestKey,
    audience: String,
    acs_url: String,
    path: String,
}

/// Create an organization, a SAML connection and a pinned key, and work out the URL the
/// identity provider would be told to post to.
async fn wire(harness: &Harness, nameid_format: &str) -> Wired {
    wire_as(harness, nameid_format, ISSUER).await
}

/// [`wire`] with the identity provider's entity id chosen by the caller.
///
/// EACH CONNECTION GETS ITS OWN ISSUER when a test wires two, and the first version of this
/// file had them SHARE one "so that resolution would find the wrong one". That is backwards: a
/// lookup keyed on an issuer two rows share is ambiguous, so a build resolving the connection
/// from the document could land on either -- including the one that then fails the signature,
/// which is the answer the test asserts. Distinct issuers make such a build resolve
/// DETERMINISTICALLY to the connection the document names, verify against its anchors, and
/// succeed. That is the outcome that separates it from a build reading the URL.
async fn wire_as(harness: &Harness, nameid_format: &str, idp_entity_id: &str) -> Wired {
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
    // PER CONNECTION, like the ACS URL. A shared audience is a second value two connections
    // agree on, and every value they agree on is one a wrong-connection test cannot see.
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
                idp_entity_id,
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
        issuer: idp_entity_id.to_owned(),
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
/// THE WINDOW IS WRITTEN AROUND THE CLOCK THE ROUTE WILL READ, which is the harness's, and an
/// earlier version of this sentence called that "the real clock, unlike `saml_acs.rs`'s
/// fixtures". It is not: the harness environment is `Env::deterministic(UNIX_EPOCH, ..)`, so
/// `now_micros` answers 0 and every window here sits in 1969-70 -- the same fixed-date shape
/// `saml_acs.rs` uses, reached a different way. Deriving the window from the seam rather than
/// writing the literals is still the right habit, because it is what keeps the fixture correct
/// if the harness clock ever moves; the contrast the sentence drew was simply not there.
fn signed(wired: &Wired, env: &Env, assertion_id: &str, name_id: &str, format: &str) -> String {
    let now = now_micros(env) / 1_000_000;
    let children = format!(
        "<saml:Issuer>{}</saml:Issuer>\
         <saml:Subject>\
         <saml:NameID Format=\"{format}\">{name_id}</saml:NameID>\
         <saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\
         <saml:SubjectConfirmationData Recipient=\"{}\" NotOnOrAfter=\"{}\"/>\
         </saml:SubjectConfirmation></saml:Subject>\
         <saml:Conditions NotBefore=\"{}\" NotOnOrAfter=\"{}\">\
         <saml:AudienceRestriction><saml:Audience>{}</saml:Audience>\
         </saml:AudienceRestriction></saml:Conditions>\
         <saml:AttributeStatement/>",
        wired.issuer,
        wired.acs_url,
        rfc3339(now + 120),
        rfc3339(now - 120),
        rfc3339(now + 120),
        wired.audience,
    );
    ironauth_saml::test_util::signed_response_with(&wired.key, assertion_id, &children)
}

/// [`signed`], for a response that answers an outstanding request.
fn signed_solicited(
    wired: &Wired,
    env: &Env,
    assertion_id: &str,
    name_id: &str,
    in_response_to: &str,
) -> String {
    let now = now_micros(env) / 1_000_000;
    let children = format!(
        "<saml:Issuer>{}</saml:Issuer>\
         <saml:Subject>\
         <saml:NameID Format=\"{NAMEID_FORMAT}\">{name_id}</saml:NameID>\
         <saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\
         <saml:SubjectConfirmationData InResponseTo=\"{in_response_to}\" Recipient=\"{}\" \
         NotOnOrAfter=\"{}\"/></saml:SubjectConfirmation></saml:Subject>\
         <saml:Conditions NotBefore=\"{}\" NotOnOrAfter=\"{}\">\
         <saml:AudienceRestriction><saml:Audience>{}</saml:Audience>\
         </saml:AudienceRestriction></saml:Conditions>\
         <saml:AttributeStatement/>",
        wired.issuer,
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

/// Every header a response carries, as a comparable list.
///
/// COMPARED IN FULL by the anti-enumeration test, because a build that leaks which connection
/// ids exist need not do it through the status or the page: one differing header -- a
/// `Cache-Control`, a `WWW-Authenticate`, anything -- is a per-request yes/no.
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

#[tokio::test]
async fn a_signed_response_is_accepted_and_signs_somebody_in() {
    // ADDING SIGN-IN HAD TO COME HERE AND SAY SO, which is what the previous version of this
    // test asked for: it asserted that no session was minted, "so that adding sign-in has to
    // come here and say so". This is that. A correctly signed, in-audience, in-window response
    // is consumed and now answers with a session cookie and a redirect.
    //
    // WHO IT SIGNS IN, and whether a second provider can name the same person, is
    // `saml_signin`'s suite. What is asserted here is only that the TRANSPORT reached it.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, NAMEID_FORMAT).await;

    let response = signed(
        &wired,
        harness.env(),
        "_assertion_ok",
        SUBJECT,
        NAMEID_FORMAT,
    );
    let (status, headers, body) = harness
        .post_form(&wired.path, &form(&response, None), None)
        .await;

    assert_eq!(status, 303, "{body}");
    assert!(
        headers
            .get_all(axum::http::header::SET_COOKIE)
            .iter()
            .any(|value| String::from_utf8_lossy(value.as_bytes()).contains("ironauth_session")),
        "the assertion consumer minted no session: {body}"
    );
    assert!(
        headers.get(axum::http::header::LOCATION).is_some(),
        "an accepted response did not redirect"
    );
}

#[tokio::test]
async fn only_the_recorded_relay_state_becomes_a_redirect_and_never_the_posted_one() {
    // THE SOLICITED PATH, which no test in the first version of this file reached -- every
    // fixture was unsolicited, so `Consumed::relay_state` was `None` everywhere and a build
    // redirecting to the POSTED field would have passed the test that claimed to forbid it.
    //
    // HERE THERE IS A RECORDED RELAYSTATE AND A POSTED ONE, and they differ. THE PREVIOUS
    // VERSION OF THIS TEST FORBADE BOTH, because this build minted no session and so redirected
    // nowhere, and its own comment said "when sign-in lands only the recorded one may". Sign-in
    // has landed, so that is now the assertion: the `Location` is the value THIS DEPLOYMENT
    // recorded when it issued the request, and the posted field reaches nothing. Taking the
    // posted one would be an open redirect with extra steps.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, NAMEID_FORMAT).await;
    let env = harness.env().clone();
    let now = now_micros(&env);
    harness
        .store()
        .scoped(harness.scope())
        .saml_replay()
        .issue_request(
            &wired.connection,
            "_req_solicited",
            Some("/authorize?client_id=cli_recorded&scope=openid"),
            now,
            now + 300_000_000,
        )
        .await
        .expect("issue the request");

    let response = signed_solicited(
        &wired,
        &env,
        "_assertion_solicited",
        SUBJECT,
        "_req_solicited",
    );
    let (status, headers, body) = harness
        .post_form(
            &wired.path,
            &form(&response, Some("https://evil.example/steal")),
            None,
        )
        .await;

    assert_eq!(status, 303, "{body}");

    // THE FIXTURE REALLY WAS SOLICITED, which nothing measured: `wire` sets
    // `allow_unsolicited: true`, so a response whose `InResponseTo` went unread would be
    // ACCEPTED as unsolicited with the identical 200 and `Consumed::relay_state` back to `None`
    // -- the exact state the previous round's fix existed to leave behind. The request row is
    // the witness: consuming it again must fail, because the response already spent it.
    let spent = harness
        .store()
        .scoped(harness.scope())
        .saml_replay()
        .consume_request(&wired.connection, "_req_solicited", now_micros(&env))
        .await;
    assert!(
        matches!(spent, Err(ironauth_store::StoreError::NotFound)),
        "the response did not spend the request it named, so it was treated as unsolicited: \
         {spent:?}"
    );
    let location = headers
        .get(axum::http::header::LOCATION)
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
        .expect("an accepted response redirects");
    assert!(
        location.contains("cli_recorded"),
        "the redirect is not the RelayState this deployment recorded: {location}"
    );
    assert!(
        !location.contains("evil.example"),
        "the POSTED RelayState became the redirect: {location}"
    );
    assert!(
        !body.contains("evil.example"),
        "the posted value was echoed: {body}"
    );
}

#[tokio::test]
async fn the_same_response_cannot_be_posted_twice() {
    // THE REPLAY CACHE, REACHED THROUGH HTTP. `saml_acs.rs` proves the store refuses the second
    // admission; this proves the route does not answer the second POST as though it had.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, NAMEID_FORMAT).await;

    let response = signed(
        &wired,
        harness.env(),
        "_assertion_once",
        SUBJECT,
        NAMEID_FORMAT,
    );
    let (first, _, body) = harness
        .post_form(&wired.path, &form(&response, None), None)
        .await;
    assert_eq!(first, 303, "{body}");

    let (second, _, body) = harness
        .post_form(&wired.path, &form(&response, None), None)
        .await;
    assert_eq!(second, 400, "a replayed response was accepted: {body}");
    assert!(
        body.contains("does not answer a sign-in this server started"),
        "the refusal was not the replay class: {body}"
    );
}

#[tokio::test]
async fn a_response_for_another_connection_is_refused_at_the_url_it_was_posted_to() {
    // THE CONNECTION COMES FROM THE PATH, NOT THE DOCUMENT, and the fixture is built so a build
    // that read the document would SUCCEED rather than fail differently. Two connections, each
    // with its OWN issuer, audience, ACS URL and pinned key: a build resolving the connection
    // from the response's `Issuer` finds the first one deterministically, verifies against its
    // anchors, matches its audience and recipient, and accepts. This build reads the path,
    // checks against the second connection's anchors, and refuses.
    let harness = Harness::start_store_backed().await;
    let first = wire_as(&harness, NAMEID_FORMAT, "urn:idp:one").await;
    let second = wire_as(&harness, NAMEID_FORMAT, "urn:idp:two").await;
    assert_ne!(first.issuer, second.issuer);

    // POSTED AT THE SECOND CONNECTION'S URL, and correct in every respect for the FIRST.
    let for_first = signed(
        &first,
        harness.env(),
        "_assertion_first",
        SUBJECT,
        NAMEID_FORMAT,
    );
    let (status, headers, body) = harness
        .post_form(&second.path, &form(&for_first, None), None)
        .await;

    assert_eq!(
        status, 400,
        "a response for another connection was accepted: {body}"
    );
    assert!(
        body.contains("not signed by a certificate this connection trusts"),
        "the refusal was not about the trust anchors: {body}"
    );
    assert_eq!(
        headers
            .get_all(axum::http::header::SET_COOKIE)
            .iter()
            .count(),
        0
    );

    // AND AT ITS OWN URL THE SAME DOCUMENT IS ACCEPTED, so the refusal above is the connection
    // and not a broken fixture.
    let (status, _, body) = harness
        .post_form(&first.path, &form(&for_first, None), None)
        .await;
    assert_eq!(status, 303, "{body}");
}

#[tokio::test]
async fn a_body_that_is_not_base64_is_refused_before_the_connection_is_read() {
    // THE GATE HAS ITS OWN SENTENCE, and the test asserts it rather than the status: a body that
    // reaches `ironauth-saml` and fails to parse answers 400 too, so a suite checking only the
    // status cannot tell the base64 gate from its absence.
    //
    // AND THE ORDER IS MEASURED, not just the sentence, by posting the undecodable body at a
    // connection id that names NO CONNECTION. If the store were consulted first the answer
    // would be the 404 that an absent connection gets; the base64 sentence can only come back
    // if the gate ran before the lookup. Asserting the sentence alone left the whole
    // decode-before-the-store block free to move below both reads with the suite green.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, NAMEID_FORMAT).await;
    let absent = SamlConnectionId::generate(harness.env(), &harness.scope());
    let absent_path = format!(
        "/t/{}/e/{}/saml/acs/{absent}",
        harness.scope().tenant(),
        harness.scope().environment()
    );

    let (status, _, body) = harness
        .post_form(&absent_path, "SAMLResponse=%7B%7Dnot-base64%21", None)
        .await;
    assert_eq!(
        status, 400,
        "the store was consulted before the body: {body}"
    );
    assert!(body.contains("not valid base64"), "{body}");

    // THE SAME BODY AT A LIVE CONNECTION IS THE SAME ANSWER, which is what says the sentence
    // above is the gate speaking and not an accident of the absent connection.
    let (status, _, body) = harness
        .post_form(&wired.path, "SAMLResponse=%7B%7Dnot-base64%21", None)
        .await;
    assert_eq!(status, 400);
    assert!(body.contains("not valid base64"), "{body}");

    // AND BASE64 OF SOMETHING THAT IS NOT XML IS A DIFFERENT SENTENCE, which is what says the
    // two are distinguishable at all.
    let (status, _, body) = harness
        .post_form(&wired.path, &form("this is not xml", None), None)
        .await;
    assert_eq!(status, 400);
    assert!(!body.contains("not valid base64"), "{body}");
    assert!(body.contains("not signed by a certificate"), "{body}");

    // NO FIELD AT ALL: axum refuses the form before the handler runs, with the status it uses
    // for a body it could not deserialize.
    let (status, _, _) = harness.post_form(&wired.path, "RelayState=%2F", None).await;
    assert_eq!(
        status, 422,
        "a form with no SAMLResponse was not refused as unprocessable"
    );
}

#[tokio::test]
async fn an_unknown_connection_answers_exactly_like_a_malformed_one() {
    // NO ENUMERATION ORACLE. Four inputs across three code paths: a well-formed id for a
    // connection that does not exist, a well-formed id belonging to ANOTHER SCOPE (which the id
    // type refuses at `parse_in_scope`), and two strings that are not ids at all. Headers are
    // compared as well as status and body, because a leak does not have to be in the page.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, NAMEID_FORMAT).await;
    let scope = harness.scope();
    let absent = SamlConnectionId::generate(harness.env(), &scope);
    let foreign_scope = ironauth_store::Scope::new(
        ironauth_store::TenantId::generate(harness.env()),
        ironauth_store::EnvironmentId::generate(harness.env()),
    );
    let foreign = SamlConnectionId::generate(harness.env(), &foreign_scope);
    let body = form(
        &signed(
            &wired,
            harness.env(),
            "_assertion_x",
            SUBJECT,
            NAMEID_FORMAT,
        ),
        None,
    );

    // AND THE BODY CLASS IS VARIED TOO, because the identity is only interesting if it holds for
    // every body: with the id parse above the body gates, an undecodable body at a malformed id
    // answered 404 while the same body at a well-formed absent id answered 400, so the pair told
    // an enumerator whether a string parses as an in-scope id. The loop below runs each id
    // against a valid signed response AND against an undecodable body.
    let mut answers = Vec::new();
    for id in [
        absent.to_string(),
        foreign.to_string(),
        "not-an-id".to_owned(),
        "smc_".to_owned(),
    ] {
        let path = format!(
            "/t/{}/e/{}/saml/acs/{id}",
            scope.tenant(),
            scope.environment()
        );
        let (status, headers, page) = harness.post_form(&path, &body, None).await;
        answers.push((status, header_shape(&headers), page));
    }
    let mut undecodable = Vec::new();
    for id in [
        absent.to_string(),
        foreign.to_string(),
        "not-an-id".to_owned(),
        "smc_".to_owned(),
    ] {
        let path = format!(
            "/t/{}/e/{}/saml/acs/{id}",
            scope.tenant(),
            scope.environment()
        );
        let (status, headers, page) = harness
            .post_form(&path, "SAMLResponse=%7B%7Dnot-base64%21", None)
            .await;
        undecodable.push((status, header_shape(&headers), page));
    }
    for answer in &undecodable[1..] {
        assert_eq!(
            answer.0, undecodable[0].0,
            "an undecodable body differs by status"
        );
        assert_eq!(
            answer.1, undecodable[0].1,
            "an undecodable body differs by header"
        );
        assert_eq!(
            answer.2, undecodable[0].2,
            "an undecodable body differs by body"
        );
    }
    assert_eq!(answers[0].0, 404);
    for answer in &answers[1..] {
        assert_eq!(answer.0, answers[0].0, "the answers differ by status");
        assert_eq!(answer.1, answers[0].1, "the answers differ by header");
        assert_eq!(answer.2, answers[0].2, "the answers differ by body");
    }
}

#[tokio::test]
async fn an_oversized_field_is_refused_without_being_decoded() {
    // THE CAP IS ON THE ENCODED FORM, which is the quantity the decode work is proportional to.
    // Just over it is refused; just under it reaches the parser and fails there, which is what
    // says the cap is the thing refusing rather than the size being unreachable.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, NAMEID_FORMAT).await;

    // OVER THE CAP AND NOT VALID BASE64: 413, not 400. A build that decoded first would answer
    // 400 here, so this is what says the cap is consulted BEFORE the decode rather than merely
    // somewhere before the store. `!` is outside the alphabet, so a decode-first build cannot
    // reach the cap at all.
    let over = format!("{}!", "A".repeat(512 * 1024 + 4));
    let (status, _, body) = harness
        .post_form(
            &wired.path,
            &format!("SAMLResponse={}", urlencode(&over)),
            None,
        )
        .await;
    assert_eq!(
        status, 413,
        "the body was decoded before the cap was consulted: {body}"
    );

    // UNDER THE CAP AND DECODABLE, so what refuses it is past both gates. The length is a
    // multiple of four deliberately: an earlier version used one that was not, so the under-cap
    // body was refused by the BASE64 gate while the comment claimed it "reaches the parser",
    // and an assertion on a bare 400 could not tell the two apart.
    let under = "A".repeat(512 * 1024 - 4);
    assert_eq!(under.len() % 4, 0, "the under-cap body must be decodable");
    let (status, _, body) = harness
        .post_form(&wired.path, &format!("SAMLResponse={under}"), None)
        .await;
    assert_eq!(
        status, 400,
        "a body under the cap was refused by the cap: {body}"
    );
    assert!(
        !body.contains("not valid base64"),
        "the under-cap body was refused by the base64 gate, not past it: {body}"
    );
}

#[tokio::test]
async fn a_line_wrapped_field_is_decoded_and_a_url_safe_one_is_not() {
    // THE ONE INTEROP BEHAVIOUR THIS ENDPOINT ADDS, and nothing measured it: identity providers
    // line-wrap the base64 field, and a conformant decoder rejects the newline. Removing the
    // whitespace strip left all seven tests green and would have refused every response from a
    // wrapping provider as "not valid base64" -- telling the operator their base64 is broken.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, NAMEID_FORMAT).await;
    let response = signed(
        &wired,
        harness.env(),
        "_assertion_wrapped",
        SUBJECT,
        NAMEID_FORMAT,
    );
    let encoded = base64::engine::general_purpose::STANDARD.encode(&response);

    let wrapped: String = encoded
        .as_bytes()
        .chunks(64)
        .map(|line| String::from_utf8_lossy(line).into_owned())
        .collect::<Vec<_>>()
        .join("\r\n");
    assert!(wrapped.contains("\r\n"), "the fixture did not wrap");
    let (status, _, body) = harness
        .post_form(
            &wired.path,
            &format!("SAMLResponse={}", urlencode(&wrapped)),
            None,
        )
        .await;
    assert_eq!(status, 303, "a line-wrapped field was not decoded: {body}");

    // AND A SPACE IS NOT STRIPPED, which is the other half of the same decision.
    // `application/x-www-form-urlencoded` turns `+` into a space, and `+` is base64 character
    // 62, so a poster who failed to percent-encode their field arrives with spaces where their
    // data had `+`. Deleting those SILENTLY REPAIRS the field into a different document, and
    // when the count is a multiple of four the repair still decodes -- to bytes the identity
    // provider never signed -- so the operator is told their certificate is wrong.
    //
    // FOUR SPACES, DELIBERATELY. A first attempt replaced every `+` with a space and asserted
    // "not valid base64", which BOTH builds answer whenever the count is not a multiple of
    // four -- so reverting the filter to `is_ascii_whitespace` left the suite green. Inserting
    // exactly four separates them with no arithmetic left to chance: a build that strips them
    // recovers the original document and answers 200, and this build cannot decode it.
    let spaced = format!("{}    {}", &encoded[..8], &encoded[8..]);
    let (status, _, body) = harness
        .post_form(
            &wired.path,
            &format!("SAMLResponse={}", urlencode(&spaced)),
            None,
        )
        .await;
    assert_eq!(
        status, 400,
        "spaces were stripped, so a mis-encoded field was repaired into a document nobody \
         signed: {body}"
    );
    assert!(
        body.contains("not valid base64"),
        "a mis-encoded field was reported as something other than a decoding fault: {body}"
    );

    // AND THE ALPHABET IS THE STANDARD ONE, which the same comment claims and nothing measured.
    // A URL-safe encoding of the identical document must not be accepted: OASIS Bindings names
    // one encoding, and quietly taking a second is a second reading of the same bytes.
    let url_safe = base64::engine::general_purpose::URL_SAFE.encode(&response);
    if url_safe == encoded {
        // The document happened to encode without `+` or `/`; nothing to distinguish.
        return;
    }
    let (status, _, body) = harness
        .post_form(
            &wired.path,
            &format!("SAMLResponse={}", urlencode(&url_safe)),
            None,
        )
        .await;
    assert_eq!(
        status, 400,
        "a URL-safe encoding was accepted where OASIS names the standard alphabet: {body}"
    );
    assert!(body.contains("not valid base64"), "{body}");
}
