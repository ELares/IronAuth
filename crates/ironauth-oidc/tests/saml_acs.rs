// SPDX-License-Identifier: MIT OR Apache-2.0

//! The assertion consumer service, end to end: a real signature, a real database, real replay.
//!
//! # Why this needs a database when the condition suite does not
//!
//! Everything `ironauth-saml` decides is a property of the document, and its suites prove those
//! against documents that genuinely verify. What THIS module decides is a property of the
//! WORLD -- was this request issued by us, is it still unspent, has this assertion been seen --
//! and none of those has a truthful in-memory double. `consume_request` is an
//! `UPDATE ... WHERE consumed_at IS NULL` and `admit_assertion` is an
//! `INSERT ... ON CONFLICT DO NOTHING`; the whole point of both is what the DATABASE does when
//! two of them race, which is exactly what a fake cannot tell you.
//!
//! # And the fixtures are signed, not stubbed
//!
//! Each response here is signed by a key pinned on the connection under test, through the same
//! `verify` the endpoint uses. A test that fed the pipeline an unsigned document would be
//! measuring the pipeline's plumbing while the thing it exists to do went unexercised.
//!
//! Needs a database.

#![cfg(feature = "testing")]

use ironauth_env::Env;
use ironauth_jose::xmldsig::test_util::XmlTestKey;
use ironauth_oidc::saml_acs::{Acs, AcsError, consume, examine};
use ironauth_saml::{Limits, Value};
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, NewSamlCertificate, NewSamlConnection, OrganizationId, SamlCertificate,
    SamlCertificateId, SamlConnection, SamlConnectionId, SamlKeyKind, Scope,
};
use serde_json::json;

const ISSUER: &str = "urn:idp";
const AUDIENCE: &str = "https://ironauth.example/saml/metadata";
const ACS_URL: &str = "https://ironauth.example/saml/acs";
const EMAIL_CLAIM: &str = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress";
/// 2026-01-01T00:00:00Z, which every window below is written around.
const NOW: i64 = 1_767_225_600;

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

async fn seed_org(db: &TestDatabase, env: &Env, scope: Scope) -> OrganizationId {
    let id = OrganizationId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .organizations(scope)
        .create(env, &id, now_micros(env), "Globex", None)
        .await
        .expect("create organization");
    id
}

/// A connection and the key pinned on it, ready to consume a response.
struct Fixture {
    scope: Scope,
    limits: Limits,
    connection: SamlConnection,
    certificates: Vec<SamlCertificate>,
    key: XmlTestKey,
}

impl Fixture {
    fn acs(&self) -> Acs<'_> {
        Acs {
            connection: &self.connection,
            certificates: &self.certificates,
            now_unix_secs: NOW,
            limits: &self.limits,
        }
    }
}

/// Create a connection, pin a freshly generated P-256 key on it, and read both back.
async fn fixture(db: &TestDatabase, env: &Env, allow_unsolicited: bool) -> Fixture {
    let scope = db.seed_scope(env).await;
    let organization = seed_org(db, env, scope).await;
    let id = SamlConnectionId::generate(env, &scope);
    let acting = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env));
    acting
        .saml_connections()
        .create(
            env,
            NewSamlConnection {
                id: &id,
                organization_id: &organization,
                display_name: "Okta",
                idp_entity_id: ISSUER,
                idp_sso_url: "https://idp.example/sso",
                sp_entity_id: AUDIENCE,
                acs_url: ACS_URL,
                allow_unsolicited,
                clock_skew_secs: 30,
                max_assertion_age_secs: 300,
                nameid_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                attribute_mapping: &json!({}),
                require_encrypted_assertion: false,
            },
            None,
            None,
        )
        .await
        .expect("create the connection");

    // THE KEY IS GENERATED AND PINNED, so the fixtures below are signed by exactly the key this
    // connection trusts -- which is what makes "the signature verified" mean anything here.
    let key = XmlTestKey::generate();
    let certificate_id = SamlCertificateId::generate(env, &scope);
    let now = now_micros(env);
    acting
        .saml_connections()
        .pin_certificate(
            env,
            NewSamlCertificate {
                id: &certificate_id,
                connection_id: &id,
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

    // READ AS THE APP ROLE, which is what the endpoint is: `ironauth_control` creates
    // connections and pins certificates, `ironauth_app` reads them and spends the request and
    // replay rows. Reading here as `control` would test a path production never takes -- and
    // 0198 grants the replay tables to `app` ALONE, so it would also have hidden that.
    let read = db.store().scoped(scope);
    let connection = read
        .saml_connections()
        .find_active(&id)
        .await
        .expect("read the connection")
        .expect("the connection is active");
    let certificates = read
        .saml_connections()
        .certificates(&id)
        .await
        .expect("read the certificates");
    Fixture {
        scope,
        limits: Limits::default(),
        connection,
        certificates,
        key,
    }
}

/// A signed response, with `in_response_to` when it answers a request.
fn signed(key: &XmlTestKey, assertion_id: &str, in_response_to: Option<&str>) -> String {
    let correlation = in_response_to.map_or(String::new(), |id| format!(" InResponseTo=\"{id}\""));
    let children = format!(
        "<saml:Issuer>{ISSUER}</saml:Issuer>\
         <saml:Subject>\
         <saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">\
         ada@globex.example</saml:NameID>\
         <saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\
         <saml:SubjectConfirmationData{correlation} Recipient=\"{ACS_URL}\" \
         NotOnOrAfter=\"2026-01-01T00:02:00Z\"/></saml:SubjectConfirmation></saml:Subject>\
         <saml:Conditions NotBefore=\"2025-12-31T23:58:00Z\" NotOnOrAfter=\"2026-01-01T00:02:00Z\">\
         <saml:AudienceRestriction><saml:Audience>{AUDIENCE}</saml:Audience>\
         </saml:AudienceRestriction></saml:Conditions>\
         <saml:AttributeStatement><saml:Attribute Name=\"{EMAIL_CLAIM}\">\
         <saml:AttributeValue>ada@globex.example</saml:AttributeValue></saml:Attribute>\
         </saml:AttributeStatement>"
    );
    ironauth_saml::test_util::signed_response_with(key, assertion_id, &children)
}

#[tokio::test]
async fn a_solicited_response_signs_somebody_in_and_spends_its_request_exactly_once() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let fixture = fixture(&db, &env, false).await;
    let replay = db.store().scoped(fixture.scope).saml_replay();

    // THE REQUEST THIS DEPLOYMENT ISSUED, with the return URL recorded beside it.
    let now = now_micros(&env);
    replay
        .issue_request(
            &fixture.connection.id,
            "_req_first",
            Some("/dashboard"),
            now,
            now + 300_000_000,
        )
        .await
        .expect("issue the request");

    let response = signed(&fixture.key, "_assertion_a", Some("_req_first"));
    let consumed = consume(&replay, &fixture.acs(), response.as_bytes())
        .await
        .expect("a genuine solicited response");

    assert_eq!(consumed.accepted.name_id, "ada@globex.example");
    assert_eq!(consumed.accepted.assertion_id, "_assertion_a");
    assert_eq!(
        consumed.accepted.in_response_to.as_deref(),
        Some("_req_first")
    );
    assert_eq!(
        consumed.relay_state.as_deref(),
        Some("/dashboard"),
        "the RelayState came from somewhere other than the store"
    );
    assert_eq!(
        consumed.statement.attributes[0].values,
        vec![Value::Text("ada@globex.example".to_owned())]
    );

    // AND THE REQUEST IS SPENT. A SECOND response answering the same request -- a different
    // assertion, so the replay cache cannot be what refuses it -- is `UnknownRequest`.
    let second = signed(&fixture.key, "_assertion_b", Some("_req_first"));
    let refused = consume(&replay, &fixture.acs(), second.as_bytes()).await;
    assert!(
        matches!(refused, Err(AcsError::UnknownRequest)),
        "an outstanding request was spendable twice: {refused:?}"
    );
}

#[tokio::test]
async fn the_same_assertion_is_admitted_once_even_on_two_requests() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let fixture = fixture(&db, &env, false).await;
    let replay = db.store().scoped(fixture.scope).saml_replay();
    let now = now_micros(&env);

    // TWO OUTSTANDING REQUESTS, so the request check cannot be what refuses the second attempt.
    // The SAME assertion id is presented against each; only the replay table can tell them apart.
    for request in ["_req_one", "_req_two"] {
        replay
            .issue_request(
                &fixture.connection.id,
                request,
                None,
                now,
                now + 300_000_000,
            )
            .await
            .expect("issue");
    }

    let first = signed(&fixture.key, "_assertion_shared", Some("_req_one"));
    consume(&replay, &fixture.acs(), first.as_bytes())
        .await
        .expect("the first presentation");

    let second = signed(&fixture.key, "_assertion_shared", Some("_req_two"));
    let refused = consume(&replay, &fixture.acs(), second.as_bytes()).await;
    assert!(
        matches!(refused, Err(AcsError::Replayed)),
        "one assertion was admitted twice: {refused:?}"
    );
}

#[tokio::test]
async fn a_refused_response_does_not_spend_the_request_it_names() {
    // THE ORDERING PROPERTY, and the reason it is not cosmetic: if a response that fails its
    // checks still consumed the request it names, anybody who can post bytes to this endpoint
    // could spend a legitimate user's outstanding request and turn their sign-in into "unknown
    // request" -- a denial of service with no authentication at all.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let fixture = fixture(&db, &env, false).await;
    let replay = db.store().scoped(fixture.scope).saml_replay();
    let now = now_micros(&env);
    replay
        .issue_request(
            &fixture.connection.id,
            "_req_victim",
            Some("/dashboard"),
            now,
            now + 300_000_000,
        )
        .await
        .expect("issue");

    // SIGNED BY THE WRONG KEY. The document names the victim's request and is otherwise perfect.
    let attacker = XmlTestKey::generate();
    let forged = signed(&attacker, "_assertion_forged", Some("_req_victim"));
    let refused = consume(&replay, &fixture.acs(), forged.as_bytes()).await;
    assert!(
        matches!(refused, Err(AcsError::Signature(_))),
        "a response signed by an unpinned key was not refused on its signature: {refused:?}"
    );

    // AND THE VICTIM'S REQUEST IS STILL THERE, which is the whole assertion.
    let genuine = signed(&fixture.key, "_assertion_genuine", Some("_req_victim"));
    let consumed = consume(&replay, &fixture.acs(), genuine.as_bytes())
        .await
        .expect("the genuine response still works");
    assert_eq!(consumed.relay_state.as_deref(), Some("/dashboard"));
}

#[tokio::test]
async fn an_unsolicited_response_is_refused_by_default_and_admitted_once_on_opt_in() {
    let db = TestDatabase::start().await;
    let env = Env::system();

    // BY DEFAULT: refused, and refused with the error that names the operator's switch rather
    // than one about the document.
    let strict = fixture(&db, &env, false).await;
    let replay = db.store().scoped(strict.scope).saml_replay();
    let response = signed(&strict.key, "_assertion_unsolicited", None);
    let refused = consume(&replay, &strict.acs(), response.as_bytes()).await;
    assert!(
        matches!(refused, Err(AcsError::UnsolicitedRefused)),
        "an unsolicited response was accepted by default: {refused:?}"
    );
}

#[tokio::test]
async fn an_unsolicited_response_on_an_opted_in_connection_is_still_replay_protected() {
    // WITH NO REQUEST TO SPEND, the assertion id is the ONLY thing between an unsolicited
    // response and unlimited reuse -- which is why the opt-in is documented as needing the
    // replay cache, and why this measures it rather than trusting the sentence.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let fixture = fixture(&db, &env, true).await;
    let replay = db.store().scoped(fixture.scope).saml_replay();

    let response = signed(&fixture.key, "_assertion_unsolicited", None);
    let consumed = consume(&replay, &fixture.acs(), response.as_bytes())
        .await
        .expect("an opted-in connection accepts an unsolicited response");
    assert_eq!(consumed.accepted.name_id, "ada@globex.example");
    assert_eq!(
        consumed.relay_state, None,
        "an unsolicited response has no request, so it can have no recorded RelayState"
    );

    let again = consume(&replay, &fixture.acs(), response.as_bytes()).await;
    assert!(
        matches!(again, Err(AcsError::Replayed)),
        "an unsolicited response was replayable: {again:?}"
    );
}

#[tokio::test]
async fn a_response_for_another_service_provider_is_refused_on_its_audience() {
    // CVE-2026-9093 THROUGH THE PIPELINE rather than through `check` alone: what this adds is
    // that the audience compared is the CONNECTION'S `sp_entity_id`, read from the row, and not
    // a constant the endpoint carries.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let fixture = fixture(&db, &env, true).await;
    let replay = db.store().scoped(fixture.scope).saml_replay();

    let elsewhere = signed(&fixture.key, "_assertion_elsewhere", None)
        .replace(AUDIENCE, "https://someone-else.example/saml/metadata");
    // The signature covers the audience, so changing it invalidates the signature -- which is
    // the point: an attacker cannot edit an audience. To measure the AUDIENCE check the document
    // has to be signed with the wrong audience in it, so it is built that way.
    let refused = consume(&replay, &fixture.acs(), elsewhere.as_bytes()).await;
    assert!(
        matches!(
            refused,
            Err(AcsError::Signature(_) | AcsError::Condition(_))
        ),
        "an assertion for another service provider was consumed: {refused:?}"
    );
}

#[tokio::test]
async fn a_connection_with_no_usable_certificate_says_so_rather_than_blaming_the_signature() {
    // AN OPERATOR WHO HAS NOT PINNED ANYTHING gets told that. "The signature did not verify"
    // would send them to look at their identity provider, which is not where the fault is.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let fixture = fixture(&db, &env, true).await;
    let response = signed(&fixture.key, "_assertion_none", None);

    let bare = Acs {
        connection: &fixture.connection,
        certificates: &[],
        now_unix_secs: NOW,
        limits: &Limits::default(),
    };
    assert!(matches!(
        examine(&bare, response.as_bytes()),
        Err(AcsError::NoTrustAnchor)
    ));

    // AND AN RSA ROW WITH NO EXPONENT IS SKIPPED RATHER THAN PANICKING. The column forbids it,
    // so such a row should not exist -- and a panic in the ACS is a denial of service somebody
    // can reach by posting a response, so the code does not rely on that.
    let mut broken = fixture.certificates.clone();
    broken[0].key_kind = SamlKeyKind::Rsa;
    broken[0].rsa_exponent = None;
    let with_broken = Acs {
        connection: &fixture.connection,
        certificates: &broken,
        now_unix_secs: NOW,
        limits: &Limits::default(),
    };
    assert!(matches!(
        examine(&with_broken, response.as_bytes()),
        Err(AcsError::NoTrustAnchor)
    ));
}

#[tokio::test]
async fn a_second_pinned_certificate_lets_a_rollover_work() {
    // A CONNECTION HOLDS SEVERAL CERTIFICATES DURING A ROLLOVER, and a response signed by any
    // pinned key must verify -- otherwise rotating one means an outage. The fixture signs with
    // the SECOND key, so a pipeline that only tried the first would fail.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let fixture = fixture(&db, &env, true).await;
    let replay = db.store().scoped(fixture.scope).saml_replay();

    let rolling = XmlTestKey::generate();
    let scope = fixture.scope;
    let certificate_id = SamlCertificateId::generate(&env, &scope);
    let now = now_micros(&env);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .saml_connections()
        .pin_certificate(
            &env,
            NewSamlCertificate {
                id: &certificate_id,
                connection_id: &fixture.connection.id,
                key_kind: SamlKeyKind::EcdsaP256,
                public_key: &rolling.public_point(),
                rsa_exponent: None,
                certificate_der: &[0x30, 0x82, 0x02],
                fingerprint_sha256: &std::iter::repeat_n(0x22_u8, 32).collect::<Vec<_>>(),
                not_before_unix_micros: now - 1_000_000,
                not_after_unix_micros: now + 86_400_000_000,
            },
            None,
            None,
        )
        .await
        .expect("pin the second certificate");

    let certificates = db
        .control_store()
        .scoped(scope)
        .saml_connections()
        .certificates(&fixture.connection.id)
        .await
        .expect("read both");
    assert_eq!(certificates.len(), 2, "the rollover fixture has one key");

    let acs = Acs {
        connection: &fixture.connection,
        certificates: &certificates,
        now_unix_secs: NOW,
        limits: &Limits::default(),
    };
    let response = signed(&rolling, "_assertion_rolled", None);
    let consumed = consume(&replay, &acs, response.as_bytes())
        .await
        .expect("a response signed by the newly pinned key");
    assert_eq!(consumed.accepted.name_id, "ada@globex.example");
}
