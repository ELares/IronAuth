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
                nameid_format: NAMEID_FORMAT,
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

    // AND EXACTLY ONE PERSON, keyed on the connection's issuer rather than on the NameID alone.
    let people = users(&harness, harness.scope()).await;
    assert_eq!(people.len(), 1, "{people:?}");
    let external = people[0].1.as_deref().expect("a federated external id");
    assert!(external.contains(ISSUER), "{external}");
    assert!(external.contains(SUBJECT), "{external}");
}

#[tokio::test]
async fn a_second_assertion_signs_in_the_same_person_rather_than_forking_the_account() {
    // JIT IS CREATE ON FIRST AND UPDATE ON SUBSEQUENT, which #139 states as one criterion
    // because the failure mode of getting the second half wrong is a duplicate account per
    // login. The identity key is the (issuer, NameID) composite, so a second assertion resolves
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
async fn one_identity_provider_cannot_name_a_person_another_one_created() {
    // THE OBJECTION THAT TOOK THE FIRST ATTEMPT APART, as a test. Migration 0196's sentence is
    // that "a trust anchor that reached two organizations would let one customer's identity
    // provider assert another customer's users", and the defect that produced it was resolving
    // the NameID through an environment-wide identifier seam. Two connections, two issuers, the
    // SAME NameID: if the key were the NameID alone, the second assertion would sign in the
    // first person and the count below would be one.
    let harness = Harness::start_store_backed().await;
    let first = wire(&harness, ISSUER, &json!({})).await;
    let second = wire(&harness, OTHER_ISSUER, &json!({})).await;

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
        &signed(&second, harness.env(), OTHER_ISSUER, "_c2", SUBJECT, &[]),
    )
    .await;
    assert_eq!(status, 303, "{body}");

    let people = users(&harness, harness.scope()).await;
    assert_eq!(
        people.len(),
        2,
        "two identity providers asserting the same NameID resolved to one account: {people:?}"
    );

    // AND EACH IS IN ITS OWN ORGANIZATION, which is the half the count alone does not show.
    let scoped = harness.db().store().scoped(harness.scope());
    for (organization, expected) in [(&first.organization, 1), (&second.organization, 1)] {
        let members = scoped
            .org_memberships()
            .list_for_org(organization, 100, None)
            .await
            .expect("list members");
        assert_eq!(members.len(), expected, "{organization}");
    }
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
    // THE MEMBERSHIP WRITE IS IDEMPOTENT, and the reason to measure it is that the read-then-
    // write shape it uses is exactly the shape that produces duplicates when the read is wrong.
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

    let (status, _, body) = post(
        &harness,
        &by_email,
        &signed(
            &by_email,
            harness.env(),
            ISSUER,
            "_f1",
            SUBJECT,
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
            "bob@globex.example",
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
async fn an_attribute_named_sub_cannot_displace_the_nameid() {
    // THE NameID IS THE IDENTITY KEY, and it reaches the mapper under `sub` because that is what
    // the shared evaluator's default subject rule reads. An identity provider that also sends an
    // attribute literally named `sub` would otherwise name one person in the signed `NameID` and
    // another in the claims every mapping is written against.
    let harness = Harness::start_store_backed().await;
    let wired = wire(&harness, ISSUER, &json!({})).await;

    let response = signed(
        &wired,
        harness.env(),
        ISSUER,
        "_g1",
        SUBJECT,
        &[("sub", "mallory@evil.example")],
    );
    let (status, _, body) = post(&harness, &wired, &response).await;
    assert_eq!(status, 303, "{body}");

    let people = users(&harness, harness.scope()).await;
    assert_eq!(people.len(), 1, "{people:?}");
    let external = people[0].1.as_deref().expect("an external id");
    assert!(
        external.contains(SUBJECT),
        "the identity was keyed on something other than the NameID: {external}"
    );
    assert!(
        !external.contains("mallory@evil.example"),
        "an attribute displaced the NameID as the identity key: {external}"
    );
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
