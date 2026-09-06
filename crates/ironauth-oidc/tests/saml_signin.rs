//! Signing in through SAML, over the real router (issue #139).
//!
//! # What these measure that the ACS suite cannot
//!
//! `saml_acs` proves an assertion is admitted or refused. Everything here starts one step later:
//! WHO the admitted assertion names locally, whether a second one names the same person, and
//! whether a provider that pinned a key on one connection can name somebody on another. That
//! last question is the one the previous change refused to answer at all, and it is the reason
//! this file exists rather than more cases in the ACS suite.
#![cfg(feature = "testing")]

mod common;

use base64::Engine as _;
use common::Harness;
use ironauth_env::Env;
use ironauth_jose::xmldsig::test_util::XmlTestKey;
use ironauth_store::{
    CorrelationId, NewSamlCertificate, NewSamlConnection, OrganizationId, SamlCertificateId,
    SamlConnectionId, SamlKeyKind, Scope,
};
use serde_json::json;

const ISSUER: &str = "urn:idp";
const OTHER_ISSUER: &str = "urn:other-idp";
const SUBJECT: &str = "ada@globex.example";
const NAMEID_FORMAT: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

struct Wired {
    connection: SamlConnectionId,
    organization: OrganizationId,
    key: XmlTestKey,
    audience: String,
    acs_url: String,
    acs_path: String,
}

/// A connection with a pinned certificate, `allow_unsolicited` on so a response needs no
/// outstanding request.
///
/// UNSOLICITED, WHICH IS A TEST-HARNESS CHOICE AND NOT A RECOMMENDATION. The solicited path is
/// driven end to end by `saml_start`; what this file varies is the identity half, and threading
/// a real `AuthnRequest` through every case would make each test measure the start endpoint
/// again while telling us nothing new about who gets signed in.
async fn wire(harness: &Harness, issuer: &str, mapping: &serde_json::Value) -> Wired {
    wire_with_format(harness, issuer, mapping, NAMEID_FORMAT).await
}

/// [`wire`] with the connection's `NameID` format chosen by the caller.
async fn wire_with_format(
    harness: &Harness,
    issuer: &str,
    mapping: &serde_json::Value,
    nameid_format: &str,
) -> Wired {
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
                idp_entity_id: issuer,
                idp_sso_url: "https://idp.example/sso",
                sp_entity_id: &audience,
                acs_url: &acs_url,
                allow_unsolicited: true,
                clock_skew_secs: 30,
                max_assertion_age_secs: 300,
                nameid_format,
                attribute_mapping: mapping,
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
        organization,
        key,
        audience,
        acs_url,
        acs_path,
    }
}

/// Register and activate a trait schema, which a mapped trait needs a version of.
///
/// SEPARATE FROM `wire` BECAUSE IT IS PER SCOPE, NOT PER CONNECTION, and because a test with an
/// empty mapping needs none: an identity with no traits is provisioned without one, which is the
/// ordinary shape for a connection whose operator has configured no attributes.
async fn seed_trait_schema(harness: &Harness) {
    let env = harness.env().clone();
    let scope = harness.scope();
    let acting = || {
        harness
            .db()
            .control_store()
            .scoped(scope)
            .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
    };
    let schema = json!({
        "type": "object",
        "properties": {"email": {"type": "string", "minLength": 3}},
        "additionalProperties": false
    })
    .to_string();
    let (_, version) = acting()
        .trait_schemas()
        .create_version(&env, &schema, 1_000_000)
        .await
        .expect("create schema version");
    acting()
        .trait_schemas()
        .activate_version(&env, version)
        .await
        .expect("activate schema version");
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

/// An unsolicited response naming `subject`, carrying `attributes` as `(Name, value)` pairs.
fn signed(
    wired: &Wired,
    env: &Env,
    issuer: &str,
    assertion_id: &str,
    subject: &str,
    attributes: &[(&str, &str)],
) -> String {
    signed_inner(
        wired,
        env,
        issuer,
        assertion_id,
        subject,
        NAMEID_FORMAT,
        attributes,
    )
}

/// [`signed`] with the `NameID`'s `Format` chosen by the caller.
///
/// THE DOCUMENT'S FORMAT MUST EQUAL THE CONNECTION'S or `examine` refuses the assertion before
/// anything this file is about can run, so a test varying one has to vary both.
fn signed_with_format(
    wired: &Wired,
    env: &Env,
    issuer: &str,
    assertion_id: &str,
    subject: &str,
    nameid_format: &str,
) -> String {
    signed_inner(
        wired,
        env,
        issuer,
        assertion_id,
        subject,
        nameid_format,
        &[],
    )
}

/// [`signed`] with the whole `AttributeStatement` written by the caller.
///
/// FOR THE CASES THE `(name, value)` SHAPE CANNOT EXPRESS, which is anything involving a
/// `NameFormat` -- and `NameFormat` is exactly what makes two attributes sharing a `Name` legal.
fn signed_with_statement(
    wired: &Wired,
    env: &Env,
    issuer: &str,
    assertion_id: &str,
    subject: &str,
    statement: &str,
) -> String {
    let now = now_micros(env) / 1_000_000;
    let children = format!(
        "<saml:Issuer>{issuer}</saml:Issuer>\
         <saml:Subject>\
         <saml:NameID Format=\"{NAMEID_FORMAT}\">{subject}</saml:NameID>\
         <saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\
         <saml:SubjectConfirmationData Recipient=\"{}\" NotOnOrAfter=\"{}\"/>\
         </saml:SubjectConfirmation></saml:Subject>\
         <saml:Conditions NotBefore=\"{}\" NotOnOrAfter=\"{}\">\
         <saml:AudienceRestriction><saml:Audience>{}</saml:Audience>\
         </saml:AudienceRestriction></saml:Conditions>{statement}",
        wired.acs_url,
        rfc3339(now + 120),
        rfc3339(now - 120),
        rfc3339(now + 120),
        wired.audience,
    );
    ironauth_saml::test_util::signed_response_with(&wired.key, assertion_id, &children)
}

fn signed_inner(
    wired: &Wired,
    env: &Env,
    issuer: &str,
    assertion_id: &str,
    subject: &str,
    nameid_format: &str,
    attributes: &[(&str, &str)],
) -> String {
    let now = now_micros(env) / 1_000_000;
    let statement = if attributes.is_empty() {
        "<saml:AttributeStatement/>".to_owned()
    } else {
        use std::fmt::Write as _;
        let mut inner = String::from("<saml:AttributeStatement>");
        for (name, value) in attributes {
            write!(
                inner,
                "<saml:Attribute Name=\"{name}\">\
                 <saml:AttributeValue>{value}</saml:AttributeValue></saml:Attribute>"
            )
            .expect("writing to a String cannot fail");
        }
        inner.push_str("</saml:AttributeStatement>");
        inner
    };
    let children = format!(
        "<saml:Issuer>{issuer}</saml:Issuer>\
         <saml:Subject>\
         <saml:NameID Format=\"{nameid_format}\">{subject}</saml:NameID>\
         <saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\
         <saml:SubjectConfirmationData Recipient=\"{}\" NotOnOrAfter=\"{}\"/>\
         </saml:SubjectConfirmation></saml:Subject>\
         <saml:Conditions NotBefore=\"{}\" NotOnOrAfter=\"{}\">\
         <saml:AudienceRestriction><saml:Audience>{}</saml:Audience>\
         </saml:AudienceRestriction></saml:Conditions>{statement}",
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

/// The nonce the solicited fixtures put in their binding cookie.
const BINDING_NONCE: &str = "test-binding-nonce";

/// A second, DIFFERENT nonce, so a test with two flows in one browser can tell them apart.
const SECOND_NONCE: &str = "test-binding-nonce-two";

/// SHA-256 of a binding nonce, which is what the request row stores.
fn binding_digest(nonce: &str) -> Vec<u8> {
    use sha2::{Digest as _, Sha256};
    Sha256::digest(nonce.as_bytes()).to_vec()
}

/// Issue an outstanding request bound to [`BINDING_NONCE`], and answer it.
///
/// THE SOLICITED PATH IS WHERE THE BROWSER BINDING LIVES, so every test about it has to go
/// through here rather than through the unsolicited fixture the rest of this file uses.
async fn signed_solicited(
    harness: &Harness,
    wired: &Wired,
    assertion_id: &str,
    request_id: &str,
    bound: bool,
) -> String {
    signed_solicited_with(
        harness,
        wired,
        assertion_id,
        request_id,
        bound.then_some(BINDING_NONCE),
    )
    .await
}

/// [`signed_solicited`] with the binding nonce chosen by the caller ([`None`] for unbound).
async fn signed_solicited_with(
    harness: &Harness,
    wired: &Wired,
    assertion_id: &str,
    request_id: &str,
    nonce: Option<&str>,
) -> String {
    let env = harness.env().clone();
    let now = now_micros(&env);
    harness
        .store()
        .scoped(harness.scope())
        .saml_replay()
        .issue_request(
            &wired.connection,
            request_id,
            Some("/dashboard"),
            nonce.map(binding_digest).as_deref(),
            now,
            now + 300_000_000,
        )
        .await
        .expect("issue the request");

    let now_secs = now / 1_000_000;
    let children = format!(
        "<saml:Issuer>{ISSUER}</saml:Issuer>\
         <saml:Subject>\
         <saml:NameID Format=\"{NAMEID_FORMAT}\">{SUBJECT}</saml:NameID>\
         <saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\
         <saml:SubjectConfirmationData InResponseTo=\"{request_id}\" Recipient=\"{}\" \
         NotOnOrAfter=\"{}\"/></saml:SubjectConfirmation></saml:Subject>\
         <saml:Conditions NotBefore=\"{}\" NotOnOrAfter=\"{}\">\
         <saml:AudienceRestriction><saml:Audience>{}</saml:Audience>\
         </saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement/>",
        wired.acs_url,
        rfc3339(now_secs + 120),
        rfc3339(now_secs - 120),
        rfc3339(now_secs + 120),
        wired.audience,
    );
    ironauth_saml::test_util::signed_response_with(&wired.key, assertion_id, &children)
}

/// POST a response with an explicit `Cookie` header.
async fn post_with_cookie(
    harness: &Harness,
    wired: &Wired,
    response: &str,
    cookie: Option<&str>,
) -> (axum::http::StatusCode, axum::http::HeaderMap, String) {
    let encoded = base64::engine::general_purpose::STANDARD.encode(response);
    harness
        .post_form(
            &wired.acs_path,
            &format!("SAMLResponse={}", urlencode(&encoded)),
            cookie,
        )
        .await
}

fn urlencode(raw: &str) -> String {
    raw.bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

/// POST a response to its connection's ACS.
async fn post(
    harness: &Harness,
    wired: &Wired,
    response: &str,
) -> (axum::http::StatusCode, axum::http::HeaderMap, String) {
    let encoded = base64::engine::general_purpose::STANDARD.encode(response);
    harness
        .post_form(
            &wired.acs_path,
            &format!("SAMLResponse={}", urlencode(&encoded)),
            None,
        )
        .await
}

/// Every user in the scope, as `(id, external_id)`.
async fn users(harness: &Harness, scope: Scope) -> Vec<(String, Option<String>)> {
    harness
        .db()
        .store()
        .scoped(scope)
        .users()
        .list(
            ironauth_store::UserListFilter {
                state: None,
                external_id: None,
                identifier: None,
            },
            1000,
            None,
        )
        .await
        .expect("list users")
        .into_iter()
        .map(|user| (user.id.to_string(), user.external_id))
        .collect()
}

fn set_cookie(headers: &axum::http::HeaderMap) -> Vec<String> {
    headers
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
        .collect()
}

#[tokio::test]
async fn a_first_assertion_provisions_the_person_and_mints_a_session() {
    // THE HEADLINE, and the thing four paragraphs of `saml_route`'s module doc were waiting for.
    // Before this change an accepted response answered 200 with a page saying signing in was not
    // enabled, so every part of the flow worked except the part it exists for.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, ISSUER, &json!({})).await;

    assert!(
        users(&harness, harness.scope()).await.is_empty(),
        "the fixture starts with a user, so provisioning cannot be observed"
    );

    let response = signed(&wired, harness.env(), ISSUER, "_a1", SUBJECT, &[]);
    let (status, headers, body) = post(&harness, &wired, &response).await;
    assert_eq!(status, 303, "{body}");

    // A SESSION COOKIE, which is what makes this a sign-in rather than an acceptance.
    let cookies = set_cookie(&headers);
    assert!(
        cookies
            .iter()
            .any(|cookie| cookie.contains("ironauth_session")),
        "no session cookie was set: {cookies:?}"
    );

    // AND EXACTLY ONE PERSON, keyed on the CONNECTION rather than on the NameID alone -- see
    // `two_organizations_sharing_one_identity_provider_are_two_people` for why the connection
    // and not the identity provider's entity id.
    let people = users(&harness, harness.scope()).await;
    assert_eq!(people.len(), 1, "{people:?}");
    let external = people[0].1.as_deref().expect("a federated external id");
    assert_eq!(
        external,
        format!(
            "saml:v1:{}:{}:{}:{SUBJECT}",
            wired.connection.to_string().len(),
            wired.connection,
            SUBJECT.len()
        ),
        "the identity key is not the connection-namespaced one"
    );
}

#[tokio::test]
async fn a_second_assertion_signs_in_the_same_person_rather_than_forking_the_account() {
    // JIT IS CREATE ON FIRST AND UPDATE ON SUBSEQUENT, which #139 states as one criterion
    // because the failure mode of getting the second half wrong is a duplicate account per
    // login. The identity key is the (connection, NameID) composite, so a second assertion resolves
    // the same row.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, ISSUER, &json!({})).await;

    for assertion in ["_b1", "_b2"] {
        let response = signed(&wired, harness.env(), ISSUER, assertion, SUBJECT, &[]);
        let (status, _, body) = post(&harness, &wired, &response).await;
        assert_eq!(status, 303, "{body}");
    }

    let people = users(&harness, harness.scope()).await;
    assert_eq!(
        people.len(),
        1,
        "a returning login forked the account: {people:?}"
    );
}

#[tokio::test]
async fn two_organizations_sharing_one_identity_provider_are_two_people() {
    // THE OBJECTION THAT TOOK THE FIRST ATTEMPT APART, as a test, and in the shape that actually
    // reaches it. Migration 0196 makes `idp_entity_id` unique per (tenant, environment,
    // ORGANIZATION) and its comment says why: "a customer with two organizations in this
    // environment signs both into their ONE identity provider tenant, so both connections carry
    // the same `idp_entity_id`". So the dangerous pair is not two DIFFERENT entity ids -- an
    // earlier version of this test used two, which any namespacing at all separates -- it is the
    // SAME entity id in two organizations, each pinning its own certificates.
    //
    // Keyed on the entity id those collapse to one local user, and whoever holds the second
    // connection's key signs in as the first organization's people. Keyed on the CONNECTION they
    // are two.
    let harness = Harness::start_store_backed().await;
    let first = wire(&harness, ISSUER, &json!({})).await;
    let second = wire(&harness, ISSUER, &json!({})).await;
    assert_ne!(
        first.organization, second.organization,
        "the fixture put both connections in one organization, so it cannot see the crossing"
    );

    let (status, _, body) = post(
        &harness,
        &first,
        &signed(&first, harness.env(), ISSUER, "_c1", SUBJECT, &[]),
    )
    .await;
    assert_eq!(status, 303, "{body}");
    let (status, _, body) = post(
        &harness,
        &second,
        &signed(&second, harness.env(), ISSUER, "_c2", SUBJECT, &[]),
    )
    .await;
    assert_eq!(status, 303, "{body}");

    let people = users(&harness, harness.scope()).await;
    assert_eq!(
        people.len(),
        2,
        "two organizations sharing an identity provider resolved to one account: {people:?}"
    );

    // AND EACH ORGANIZATION HOLDS A DIFFERENT ONE OF THEM, which a count cannot show: an earlier
    // version asserted `members.len() == 1` for each, which is equally true of a build that put
    // the SAME person in both.
    let scoped = harness.db().store().scoped(harness.scope());
    let mut members_by_org = Vec::new();
    for organization in [&first.organization, &second.organization] {
        let members = scoped
            .org_memberships()
            .list_for_org(organization, 100, None)
            .await
            .expect("list members");
        assert_eq!(members.len(), 1, "{organization}");
        members_by_org.push(members[0].user_id.to_string());
    }
    assert_ne!(
        members_by_org[0], members_by_org[1],
        "one person is a member of both organizations, so the two connections resolved to one \
         account: {members_by_org:?}"
    );
}

#[tokio::test]
async fn a_response_presented_without_the_binding_cookie_signs_nobody_in() {
    // LOGIN CSRF, which sign-in created and the browser binding closes. Mallory starts a flow,
    // authenticates at the identity provider AS HERSELF, captures the response, and auto-submits
    // it into a victim's browser. Every check upstream of the binding passes: the signature is
    // genuine, the conditions hold, the assertion is fresh, and the outstanding request is one
    // this deployment really issued and has not spent. What the victim's browser does not carry
    // is the cookie that request was issued to, and without the binding the victim ends up
    // signed into MALLORY'S account -- where everything they then do is hers to read.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, ISSUER, &json!({})).await;

    let response = signed_solicited(&harness, &wired, "_csrf1", "_req_csrf1", true).await;
    let (status, headers, body) = post_with_cookie(&harness, &wired, &response, None).await;
    assert!(status.is_client_error(), "{status} {body}");
    assert!(
        set_cookie(&headers).is_empty(),
        "a response with no binding cookie minted a session"
    );
    assert!(
        users(&harness, harness.scope()).await.is_empty(),
        "a response with no binding cookie provisioned somebody"
    );
}

#[tokio::test]
async fn a_response_presented_with_another_flows_cookie_signs_nobody_in() {
    // THE SHARPER HALF: the victim's browser is not cookie-less, it carries a binding from its
    // OWN earlier flow. A check that only asked "is there a cookie" would pass this.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, ISSUER, &json!({})).await;

    let response = signed_solicited(&harness, &wired, "_csrf2", "_req_csrf2", true).await;
    let (status, headers, body) = post_with_cookie(
        &harness,
        &wired,
        &response,
        Some("__Host-ironauth_saml_bind__req_csrf2=somebody-elses-nonce"),
    )
    .await;
    assert!(status.is_client_error(), "{status} {body}");
    assert!(set_cookie(&headers).is_empty(), "{body}");
    assert!(users(&harness, harness.scope()).await.is_empty(), "{body}");
}

#[tokio::test]
async fn a_bound_response_in_its_own_browser_signs_in() {
    // THE CONTROL, and it is what keeps the two tests above from passing on a build that refuses
    // every solicited response. Same fixture, same request, the RIGHT cookie.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, ISSUER, &json!({})).await;

    let response = signed_solicited(&harness, &wired, "_bound1", "_req_bound1", true).await;
    let (status, headers, body) = post_with_cookie(
        &harness,
        &wired,
        &response,
        Some(&format!(
            "__Host-ironauth_saml_bind__req_bound1={BINDING_NONCE}"
        )),
    )
    .await;
    assert_eq!(status, 303, "{body}");
    assert!(
        set_cookie(&headers)
            .iter()
            .any(|cookie| cookie.contains("ironauth_session")),
        "the bound response minted no session"
    );
    // AND IT LANDS ON THE RECORDED RelayState rather than anywhere the POST named.
    assert_eq!(
        headers
            .get(axum::http::header::LOCATION)
            .map(|value| value.to_str().unwrap_or_default()),
        Some("/dashboard")
    );
}

#[tokio::test]
async fn a_transient_nameid_format_signs_nobody_in() {
    // A FORMAT THAT NAMES A DIFFERENT STRING EVERY LOGIN cannot key an account: each assertion
    // would provision a new person and a new membership, so an operator's member list fills with
    // strangers who are all one person. The connection's column also travels outward, in the
    // metadata document and in every AuthnRequest's NameIDPolicy, so a connection configured
    // this way is asking its provider for exactly what this deployment cannot use.
    let harness = Harness::start_store_backed().await;
    let wired = wire_with_format(
        &harness,
        ISSUER,
        &json!({}),
        "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
    )
    .await;

    let response = signed_with_format(
        &wired,
        harness.env(),
        ISSUER,
        "_transient1",
        "_opaque_9f3a",
        "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
    );
    let (status, headers, body) = post(&harness, &wired, &response).await;
    assert!(status.is_server_error(), "{status} {body}");
    assert!(set_cookie(&headers).is_empty(), "{body}");
    assert!(
        users(&harness, harness.scope()).await.is_empty(),
        "a transient NameID provisioned an account that no second login could ever find again"
    );
}

#[tokio::test]
async fn an_assertion_naming_one_claim_twice_signs_nobody_in() {
    // TWO VALUES FOR ONE KEY IS NOT A CHOICE TO MAKE SILENTLY. SAML admits two `Attribute`
    // elements sharing a `Name` when their `NameFormat` differs, and the claims object the
    // shared mapper reads has nowhere to put a format -- so an earlier version kept the first
    // and dropped the second, handing a mapping author the wrong one of two addresses with a
    // login that looked fine. The refusal names the key in the log, which is the only way the
    // operator learns to fix it.
    let harness = Harness::start_store_backed().await;
    // THE SCHEMA IS SEEDED, and without it this test was vacuous: with no active trait schema a
    // mapping that resolves any trait fails the write and answers the SAME 500 this asserts, so
    // deleting the collision refusal left the test green. Seeding it means the only remaining
    // route to a 500 is the refusal itself.
    seed_trait_schema(&harness).await;
    let wired = wire(
        &harness,
        ISSUER,
        &json!({"traits": {"email": {"source": ["email"], "required": false}}}),
    )
    .await;

    // TWO `Name="email"` ATTRIBUTES WITH DIFFERENT `NameFormat`s, which is the pair SAML admits
    // as distinct and the claims object cannot hold. An identical pair -- same Name, same format
    // -- is refused one layer earlier by `ironauth-saml`'s own duplicate check, so a fixture
    // built that way would answer 400 without this module's rule ever running, and would pass
    // with the rule deleted.
    let statement = concat!(
        "<saml:AttributeStatement>",
        "<saml:Attribute Name=\"email\" ",
        "NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">",
        "<saml:AttributeValue>ada@globex.example</saml:AttributeValue></saml:Attribute>",
        "<saml:Attribute Name=\"email\" ",
        "NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\">",
        "<saml:AttributeValue>ada@evil.example</saml:AttributeValue></saml:Attribute>",
        "</saml:AttributeStatement>"
    );
    let response =
        signed_with_statement(&wired, harness.env(), ISSUER, "_dupe1", SUBJECT, statement);
    let (status, headers, body) = post(&harness, &wired, &response).await;
    assert!(status.is_server_error(), "{status} {body}");
    assert!(set_cookie(&headers).is_empty(), "{body}");
    assert!(users(&harness, harness.scope()).await.is_empty(), "{body}");
}

#[tokio::test]
async fn an_attribute_that_would_overwrite_the_nameid_signs_nobody_in() {
    // THE `sub` CASE, which is the same rule. The NameID is placed under `sub` because that is
    // what the shared evaluator's default subject rule reads, so a provider that also sends an
    // attribute literally named `sub` is naming one person in the signed NameID and another in
    // the claims every mapping is written against.
    //
    // AN EARLIER VERSION OF THIS TEST ASSERTED THE SIGN-IN SUCCEEDED with the NameID winning,
    // and it passed with the guard deleted: the NameID was inserted first and the attribute
    // insert used `or_insert`, which does not overwrite. The property was forced by code the
    // guard was not part of, so the test measured nothing.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, ISSUER, &json!({})).await;

    let response = signed(
        &wired,
        harness.env(),
        ISSUER,
        "_sub1",
        SUBJECT,
        &[("sub", "mallory@evil.example")],
    );
    let (status, headers, body) = post(&harness, &wired, &response).await;
    assert!(status.is_server_error(), "{status} {body}");
    assert!(set_cookie(&headers).is_empty(), "{body}");
    assert!(
        users(&harness, harness.scope()).await.is_empty(),
        "an assertion that named the subject twice signed somebody in"
    );
}

#[tokio::test]
async fn the_person_joins_the_connections_own_organization() {
    // "SAML CONNECTIONS ATTACH TO ORGANIZATIONS EXACTLY LIKE OIDC CONNECTIONS" is a #139
    // sentence, and a session minted without the membership would satisfy every other assertion
    // in this file while leaving the person invisible to every org-scoped reader downstream.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, ISSUER, &json!({})).await;

    let response = signed(&wired, harness.env(), ISSUER, "_d1", SUBJECT, &[]);
    let (status, _, body) = post(&harness, &wired, &response).await;
    assert_eq!(status, 303, "{body}");

    let people = users(&harness, harness.scope()).await;
    let user_id =
        ironauth_store::UserId::parse_in_scope(&people[0].0, &harness.scope()).expect("a user id");
    let membership = harness
        .db()
        .store()
        .scoped(harness.scope())
        .org_memberships()
        .for_user_in_org(&wired.organization, &user_id)
        .await
        .expect("read the membership");
    assert!(
        membership.is_some(),
        "the person was signed in without joining the connection's organization"
    );
}

#[tokio::test]
async fn a_repeated_assertion_does_not_add_a_second_membership() {
    // THE MEMBERSHIP WRITE IS IDEMPOTENT. An earlier version of this comment credited a
    // read-then-write guard in `ensure_membership` for that, and the guard turned out to be
    // removable without changing this test's answer: the store's own `ON CONFLICT DO NOTHING`
    // was already doing the work. The guard is gone, and what this measures is the property
    // rather than a particular implementation of it.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, ISSUER, &json!({})).await;

    for assertion in ["_e1", "_e2", "_e3"] {
        let response = signed(&wired, harness.env(), ISSUER, assertion, SUBJECT, &[]);
        let (status, _, body) = post(&harness, &wired, &response).await;
        assert_eq!(status, 303, "{body}");
    }

    let members = harness
        .db()
        .store()
        .scoped(harness.scope())
        .org_memberships()
        .list_for_org(&wired.organization, 100, None)
        .await
        .expect("list members");
    assert_eq!(
        members.len(),
        1,
        "three logins produced {} memberships",
        members.len()
    );
}

#[tokio::test]
async fn the_traits_come_from_the_connections_own_mapping_and_not_from_a_constant() {
    // #139 CRITERION 6: "attribute mapping and NameID handling round-trip through the shared JIT
    // mapper with per-connection config". Two connections, two mappings, one assertion shape --
    // so a hardcoded "read the `email` attribute" passes for the first and fails for the second.
    let harness = Harness::start_store_backed().await;
    seed_trait_schema(&harness).await;
    let by_email = wire(
        &harness,
        ISSUER,
        &json!({"traits": {"email": {"source": ["email"], "required": false}}}),
    )
    .await;
    let by_urn = wire(
        &harness,
        OTHER_ISSUER,
        &json!({
            "traits": {
                "email": {"source": ["urn:oid:0.9.2342.19200300.100.1.3"], "required": false}
            }
        }),
    )
    .await;

    // THE MAPPED ANSWER DIFFERS FROM THE NameID, which an earlier version of this fixture did
    // not arrange: it signed in `ada@globex.example` and expected the mapped email to be
    // `ada@globex.example` too, so a build that ignored every `source` and wrote the NameID into
    // every trait passed. Here the NameID is a directory id and the address is an attribute, so
    // only a build that actually read the mapping can produce it.
    let (status, _, body) = post(
        &harness,
        &by_email,
        &signed(
            &by_email,
            harness.env(),
            ISSUER,
            "_f1",
            "uid=ada,ou=people",
            &[
                ("email", "ada@globex.example"),
                ("urn:oid:0.9.2342.19200300.100.1.3", "wrong@x"),
            ],
        ),
    )
    .await;
    assert_eq!(status, 303, "{body}");

    let (status, _, body) = post(
        &harness,
        &by_urn,
        &signed(
            &by_urn,
            harness.env(),
            OTHER_ISSUER,
            "_f2",
            "uid=bob,ou=people",
            &[
                ("email", "wrong@x"),
                ("urn:oid:0.9.2342.19200300.100.1.3", "bob@globex.example"),
            ],
        ),
    )
    .await;
    assert_eq!(status, 303, "{body}");

    // EACH READ THE ATTRIBUTE ITS OWN MAPPING NAMED, and the fixtures are built so that reading
    // the other one produces `wrong@x` rather than nothing: an absent trait and a trait read
    // from the wrong attribute are different failures, and only one of them is visible in a
    // presence check.
    let traits = trait_emails(&harness).await;
    assert!(
        traits.contains(&"ada@globex.example".to_owned()),
        "the first connection's mapping was not applied: {traits:?}"
    );
    assert!(
        traits.contains(&"bob@globex.example".to_owned()),
        "the second connection's mapping was not applied: {traits:?}"
    );
    assert!(
        !traits.contains(&"wrong@x".to_owned()),
        "a connection read the other connection's attribute: {traits:?}"
    );
}

/// Every provisioned identity's mapped `email` trait.
async fn trait_emails(harness: &Harness) -> Vec<String> {
    let scoped = harness.db().store().scoped(harness.scope());
    let mut found = Vec::new();
    for (id, _) in users(harness, harness.scope()).await {
        let user_id =
            ironauth_store::UserId::parse_in_scope(&id, &harness.scope()).expect("a user id");
        if let Ok(Some((_, traits))) = scoped.users().traits(&user_id).await
            && let Some(email) = traits.get("email").and_then(serde_json::Value::as_str)
        {
            found.push(email.to_owned());
        }
    }
    found
}

#[tokio::test]
async fn a_fenced_account_is_refused_and_joins_no_organization() {
    // A FENCED ACCOUNT IS REFUSED AND NOTHING IS WRITTEN FOR IT. This test was named for the
    // ORDER of two writes -- membership after `establish_session` -- and that is no longer what
    // it reaches: round 2 added a lifecycle read BEFORE provisioning, so a fenced account is
    // turned away earlier and never gets to the membership code at all.
    //
    // NO STATE PASSES ONE CHECK AND FAILS THE OTHER, because both use `can_authenticate()`, so
    // the ordering below the earlier read is not observable from here and this test cannot
    // pretend to measure it. What it measures is the property that matters to an operator:
    // whatever the route, a person this deployment refuses to authenticate gains nothing. The
    // ordering remains correct as defence in depth if the earlier read is ever narrowed.
    //
    // THE SECOND MEMBERSHIP IS THE ONE THAT MATTERS. The first login is genuine and creates
    // both. The operator then disables the account and removes the membership; a further
    // assertion must add neither.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, ISSUER, &json!({})).await;

    let (status, _, body) = post(
        &harness,
        &wired,
        &signed(&wired, harness.env(), ISSUER, "_fence1", SUBJECT, &[]),
    )
    .await;
    assert_eq!(status, 303, "{body}");
    let people = users(&harness, harness.scope()).await;
    let user_id =
        ironauth_store::UserId::parse_in_scope(&people[0].0, &harness.scope()).expect("a user id");

    let scoped = harness.db().store().scoped(harness.scope());
    let membership = scoped
        .org_memberships()
        .for_user_in_org(&wired.organization, &user_id)
        .await
        .expect("read")
        .expect("the first login joined the organization");
    harness
        .db()
        .store()
        .scoped(harness.scope())
        .acting(
            harness.db().test_actor(harness.env()),
            CorrelationId::generate(harness.env()),
        )
        .org_memberships()
        .remove(harness.env(), &membership.id)
        .await
        .expect("remove the membership");
    harness
        .set_user_state(&people[0].0, ironauth_store::UserState::Disabled)
        .await;

    // A GENUINE, FRESH ASSERTION for the disabled person.
    let (status, headers, body) = post(
        &harness,
        &wired,
        &signed(&wired, harness.env(), ISSUER, "_fence2", SUBJECT, &[]),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert!(
        set_cookie(&headers).is_empty(),
        "a fenced account minted a session"
    );
    // NOT A 500, which is what an earlier version answered: reporting a server fault for a
    // deliberate administrative state sends an operator hunting a bug that is not there.
    assert!(
        !body.contains("could not be completed"),
        "the fenced refusal was reported as a server fault: {body}"
    );
    assert!(
        scoped
            .org_memberships()
            .for_user_in_org(&wired.organization, &user_id)
            .await
            .expect("read")
            .is_none(),
        "a refused sign-in re-joined the person to the organization"
    );
}

#[tokio::test]
async fn a_fenced_accounts_stored_identity_is_not_rewritten() {
    // THE WRITE THAT LANDS BEFORE THE FENCE. `establish_session` is given a USER ID, so the user
    // must exist before it can be asked about them -- which means provisioning, and provisioning
    // REFRESHES a returning person's mapped traits. Without a lifecycle read of its own, an
    // unauthenticated cross-site POST rewrote a disabled person's stored identity from whatever
    // their identity provider now said, on a sign-in this deployment then refused. The module
    // doc claimed "nothing lands for a person who is not admitted" while exactly that landed.
    let harness = Harness::start_store_backed().await;
    seed_trait_schema(&harness).await;
    let wired = wire(
        &harness,
        ISSUER,
        &json!({"traits": {"email": {"source": ["email"], "required": false}}}),
    )
    .await;

    let (status, _, body) = post(
        &harness,
        &wired,
        &signed(
            &wired,
            harness.env(),
            ISSUER,
            "_frozen1",
            SUBJECT,
            &[("email", "before@globex.example")],
        ),
    )
    .await;
    assert_eq!(status, 303, "{body}");
    assert_eq!(trait_emails(&harness).await, vec!["before@globex.example"]);

    let people = users(&harness, harness.scope()).await;
    harness
        .set_user_state(&people[0].0, ironauth_store::UserState::Disabled)
        .await;

    // A GENUINE ASSERTION carrying a DIFFERENT address. Refused -- and the stored one unchanged.
    let (status, _, body) = post(
        &harness,
        &wired,
        &signed(
            &wired,
            harness.env(),
            ISSUER,
            "_frozen2",
            SUBJECT,
            &[("email", "after@globex.example")],
        ),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(
        trait_emails(&harness).await,
        vec!["before@globex.example"],
        "a refused sign-in rewrote a fenced account's stored identity"
    );
}

#[tokio::test]
async fn the_jit_membership_reaches_the_event_feed() {
    // THE OUTBOUND SCIM PUSH SHIPPED IN THIS MILESTONE drives its steady state entirely from the
    // event feed, so a membership committed with no envelope is a person who exists here and
    // never reaches the downstream directory. An earlier version called the four-argument
    // `create`, which forwards no event, and nothing noticed because every other assertion in
    // this file reads the row rather than the feed.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, ISSUER, &json!({})).await;

    let (status, _, body) = post(
        &harness,
        &wired,
        &signed(&wired, harness.env(), ISSUER, "_evt1", SUBJECT, &[]),
    )
    .await;
    assert_eq!(status, 303, "{body}");

    // POLLED, NOT READ ONCE. The feed holds back rows behind a CLUSTER-WIDE snapshot watermark,
    // so a sibling test with an open transaction delays this scope's own rows -- which made a
    // single read pass alone and fail in the suite. Waiting is the correct fix rather than a
    // flake workaround: the guarantee the feed offers is eventual visibility in order.
    let mut kinds: Vec<String> = Vec::new();
    for _ in 0..50 {
        let events = harness
            .db()
            .store()
            .scoped(harness.scope())
            .outbox()
            .events_after(0, 200)
            .await
            .expect("read the feed");
        kinds = events
            .iter()
            .filter_map(|message| message.payload.get("type")?.as_str().map(str::to_owned))
            .collect();
        if kinds.iter().any(|kind| kind == "organization.member_added") {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("the JIT membership enqueued no member_added envelope: {kinds:?}");
}

#[tokio::test]
async fn a_deeply_dotted_attribute_name_does_not_abort_the_process() {
    // A DENIAL OF SERVICE ON THE WHOLE DEPLOYMENT, introduced by the dotted-path fix that made
    // realistic attribute names addressable. Nothing upstream bounds an `Attribute` `Name`:
    // `max_name_bytes` applies to the XML attribute KEY (`Name`, four bytes), not its value. So
    // a signed assertion inside the body cap can carry a name of hundreds of thousands of dots,
    // and one nested map per segment is a `serde_json::Value` that deep -- whose derived
    // recursive destructor overflows the worker stack when it drops, aborting the process for
    // every tenant. A stack overflow is not a panic: nothing catches it.
    //
    // THE TEST SURVIVING IS THE ASSERTION. If the bound is removed this does not fail, it takes
    // the test binary down with it -- verified by removing it: the suite prints "fatal runtime
    // error: stack overflow, aborting" and dies on signal 6.
    //
    // IT NO LONGER ASSERTS A REFUSAL. The first version of the bound refused the whole sign-in,
    // and that turned out to lock out every Shibboleth deployment, so an unplaceable name now
    // SKIPS the attribute. The person is signed in without it, which is what the assertions
    // below say.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, ISSUER, &json!({})).await;

    let name = ".".repeat(200_000);
    let statement = format!(
        "<saml:AttributeStatement><saml:Attribute Name=\"{name}\">\
         <saml:AttributeValue>x</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>"
    );
    let response =
        signed_with_statement(&wired, harness.env(), ISSUER, "_deep1", SUBJECT, &statement);
    let (status, headers, body) = post(&harness, &wired, &response).await;
    assert_eq!(status, 303, "{body}");
    assert!(
        set_cookie(&headers)
            .iter()
            .any(|cookie| cookie.contains("ironauth_session")),
        "{body}"
    );
    // AND THE NAME REACHED NOTHING: the connection maps no traits, so the only observable is
    // that one person exists and the process is still here to say so.
    assert_eq!(users(&harness, harness.scope()).await.len(), 1);
}

#[tokio::test]
async fn a_shibboleth_edu_person_attribute_signs_in_and_maps() {
    // THE BOUND THAT LOCKED OUT AN ENTIRE FEDERATION. Round 2 capped the dotted path at TEN
    // segments and justified it as "above every real name", miscounting its own example --
    // `urn:oid:0.9.2342.19200300.100.1.3` is SEVEN, not six. The eduPerson arc is ELEVEN:
    // `urn:oid:1.3.6.1.4.1.5923.1.1.1.6` is eduPersonPrincipalName, the default release of every
    // InCommon and eduGAIN identity provider. At ten, any IdP releasing one refused EVERY login
    // on that connection, permanently, with the request and assertion id already burned.
    //
    // THE NAME IS REAL AND SO IS THE MAPPING: this maps a trait THROUGH that name, so a build
    // that skipped the attribute rather than placing it fails here too.
    let harness = Harness::start_store_backed().await;
    seed_trait_schema(&harness).await;
    let wired = wire(
        &harness,
        ISSUER,
        &json!({
            "traits": {
                "email": {"source": ["urn:oid:1.3.6.1.4.1.5923.1.1.1.6"], "required": false}
            }
        }),
    )
    .await;

    let response = signed(
        &wired,
        harness.env(),
        ISSUER,
        "_edu1",
        "uid=ada,ou=people",
        &[("urn:oid:1.3.6.1.4.1.5923.1.1.1.6", "ada@globex.example")],
    );
    let (status, _, body) = post(&harness, &wired, &response).await;
    assert_eq!(
        status, 303,
        "an eduPerson attribute name refused the sign-in: {body}"
    );
    assert_eq!(trait_emails(&harness).await, vec!["ada@globex.example"]);
}

#[tokio::test]
async fn an_unmappable_deep_name_beside_a_mapped_one_does_not_refuse_the_sign_in() {
    // A NAME TOO DEEP TO PLACE SKIPS THE ATTRIBUTE, NOT THE SIGN-IN. Round 2's bound refused the
    // whole response, so an identity provider that added one exotic attribute locked out every
    // user -- and the refusal was reported to the operator as a duplicate claim name, a
    // diagnosis that was false and prescribed a repair that did not exist.
    let harness = Harness::start_store_backed().await;
    seed_trait_schema(&harness).await;
    let wired = wire(
        &harness,
        ISSUER,
        &json!({"traits": {"email": {"source": ["email"], "required": false}}}),
    )
    .await;

    let deep = "a.".repeat(200) + "b";
    let response = signed(
        &wired,
        harness.env(),
        ISSUER,
        "_skip1",
        "uid=ada,ou=people",
        &[("email", "ada@globex.example"), (&deep, "ignored")],
    );
    let (status, _, body) = post(&harness, &wired, &response).await;
    assert_eq!(
        status, 303,
        "one deep name refused the whole sign-in: {body}"
    );
    // AND THE MAPPED ATTRIBUTE BESIDE IT STILL ARRIVED, which is what "skip the attribute"
    // has to mean: dropping the claims object instead would leave the trait unset.
    assert_eq!(trait_emails(&harness).await, vec!["ada@globex.example"]);
}

#[tokio::test]
async fn a_padded_transient_format_column_is_still_transient() {
    // THE TWO SIDES MUST NORMALIZE ALIKE. `saml_acs` XSD-collapses both the connection's
    // `nameid_format` column and the document's `Format` before comparing them, so a column
    // holding the transient URI with a trailing space ADMITS a flush transient assertion. An
    // earlier version of the refusal below compared the column raw, so exactly that connection
    // sailed past the guard and provisioned a new person and a new membership on every login.
    let harness = Harness::start_store_backed().await;
    let wired = wire_with_format(
        &harness,
        ISSUER,
        &json!({}),
        "urn:oasis:names:tc:SAML:2.0:nameid-format:transient ",
    )
    .await;

    let response = signed_with_format(
        &wired,
        harness.env(),
        ISSUER,
        "_padded1",
        "_opaque_1",
        "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
    );
    let (status, headers, body) = post(&harness, &wired, &response).await;
    assert!(status.is_server_error(), "{status} {body}");
    assert!(
        users(&harness, harness.scope()).await.is_empty(),
        "a padded transient format bypassed the refusal: {body}"
    );
    assert!(set_cookie(&headers).is_empty(), "{body}");
}

#[tokio::test]
async fn two_flows_in_one_browser_do_not_destroy_each_other() {
    // ONE COOKIE SLOT PER HOST WAS ONE FLOW PER BROWSER. `__Host-` forbids a Domain and pins
    // `Path=/`, so a single fixed cookie name has exactly one slot: a second sign-in started in
    // another tab overwrote the first flow's nonce, and the first response then spent its
    // request and burned its assertion id before the transport compared cookies -- refused, with
    // nothing left to retry. Two tabs is not an attack.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, ISSUER, &json!({})).await;

    // TWO FLOWS, in the order a browser would hold them: the second is the one whose cookie a
    // single-slot scheme would keep.
    let first = signed_solicited(&harness, &wired, "_two1", "_req_two1", true).await;
    let second =
        signed_solicited_with(&harness, &wired, "_two2", "_req_two2", Some(SECOND_NONCE)).await;
    // TWO DIFFERENT NONCES, one per flow. An earlier version put the SAME nonce in both cookies,
    // which made the test pass on a build that ignored the request id and took whichever cookie
    // it found first -- the very selection this exists to measure.
    let jar = format!(
        "__Host-ironauth_saml_bind__req_two1={BINDING_NONCE}; \
         __Host-ironauth_saml_bind__req_two2={SECOND_NONCE}"
    );

    for (assertion, response) in [("_two2", &second), ("_two1", &first)] {
        let (status, _, body) = post_with_cookie(&harness, &wired, response, Some(&jar)).await;
        assert_eq!(
            status, 303,
            "the {assertion} flow was destroyed by the other: {body}"
        );
    }
}

#[tokio::test]
async fn a_refused_response_signs_nobody_in() {
    // THE OTHER DIRECTION, and worth its own test because everything above proves the accept
    // path: a response the ACS refuses must leave no user, no membership and no cookie. A
    // sign-in that ran before the checks would pass every test in this file.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, ISSUER, &json!({})).await;
    let other = wire(&harness, ISSUER, &json!({})).await;

    // SIGNED BY A KEY PINNED ON ANOTHER CONNECTION, which is a real signature over a real
    // assertion that this connection has no anchor for.
    let response = signed(&other, harness.env(), ISSUER, "_h1", SUBJECT, &[]);
    let (status, headers, body) = post(&harness, &wired, &response).await;
    assert!(status.is_client_error(), "{status} {body}");
    assert!(set_cookie(&headers).is_empty(), "a refusal set a cookie");
    assert!(
        users(&harness, harness.scope()).await.is_empty(),
        "a refused response provisioned somebody"
    );
}
