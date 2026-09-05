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
use ironauth_saml::{ConditionError, Limits, Unreadable, Value};
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
const NAMEID_FORMAT: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
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

/// The connection columns a test varies. Everything else about the row is fixed.
struct Settings {
    allow_unsolicited: bool,
    nameid_format: &'static str,
    require_encrypted_assertion: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            allow_unsolicited: false,
            nameid_format: NAMEID_FORMAT,
            require_encrypted_assertion: false,
        }
    }
}

/// [`fixture_with`] varying only the one column most tests care about.
async fn fixture(db: &TestDatabase, env: &Env, allow_unsolicited: bool) -> Fixture {
    fixture_with(
        db,
        env,
        Settings {
            allow_unsolicited,
            ..Settings::default()
        },
    )
    .await
}

/// Create a connection, pin a freshly generated P-256 key on it, and read both back.
async fn fixture_with(db: &TestDatabase, env: &Env, settings: Settings) -> Fixture {
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
                allow_unsolicited: settings.allow_unsolicited,
                clock_skew_secs: 30,
                max_assertion_age_secs: 300,
                nameid_format: settings.nameid_format,
                attribute_mapping: &json!({}),
                require_encrypted_assertion: settings.require_encrypted_assertion,
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

/// The children of a response, composed so one test can vary ONE value and still SIGN it.
///
/// # Varying after signing measures the signature, not the value
///
/// An earlier version built a wrong-audience fixture with `.replace(AUDIENCE, ..)` on the signed
/// bytes. `saml:Audience` is inside the digest, so the document failed at `verify` and the test
/// -- which accepted `Signature(_) | Condition(_)` -- passed on the wrong arm. NO test in this
/// file reached `AcsError::Condition` or `AcsError::Attributes` at all, so the module's headline
/// property ("nothing is spent until every stateless check passes") was measured for the
/// SIGNATURE only: moving `check` and `attributes` to after both store writes left all eight
/// tests green.
///
/// Every field here is substituted BEFORE signing, so a refusal past `verify` is reachable.
struct Body {
    audience: &'static str,
    recipient: &'static str,
    name_id_format: &'static str,
    not_on_or_after: &'static str,
    in_response_to: Option<&'static str>,
    /// A second `Attribute` with the same `Name`, which the attribute reader refuses.
    duplicate_attribute: bool,
    /// An `EncryptedAttribute`, which the reader counts and the endpoint refuses.
    encrypted_attribute: bool,
}

impl Default for Body {
    /// A body every check accepts. Each test changes exactly one field.
    fn default() -> Self {
        Self {
            audience: AUDIENCE,
            recipient: ACS_URL,
            name_id_format: NAMEID_FORMAT,
            not_on_or_after: "2026-01-01T00:02:00Z",
            in_response_to: None,
            duplicate_attribute: false,
            encrypted_attribute: false,
        }
    }
}

/// Sign `body` as an assertion with this id.
fn signed_body(key: &XmlTestKey, assertion_id: &str, body: &Body) -> String {
    let correlation = body
        .in_response_to
        .map_or(String::new(), |id| format!(" InResponseTo=\"{id}\""));
    let duplicate = if body.duplicate_attribute {
        format!(
            "<saml:Attribute Name=\"{EMAIL_CLAIM}\">\
             <saml:AttributeValue>attacker@evil.example</saml:AttributeValue></saml:Attribute>"
        )
    } else {
        String::new()
    };
    let encrypted = if body.encrypted_attribute {
        // ENOUGH TO BE COUNTED, which is what this fixture is for: the reader counts the element
        // by name and never opens it, so a placeholder body measures the endpoint's decision
        // without dragging a key exchange into a test about refusing.
        "<saml:EncryptedAttribute><xenc:EncryptedData \
         xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"/></saml:EncryptedAttribute>"
    } else {
        ""
    };
    let children = format!(
        "<saml:Issuer>{ISSUER}</saml:Issuer>\
         <saml:Subject>\
         <saml:NameID Format=\"{}\">ada@globex.example</saml:NameID>\
         <saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\
         <saml:SubjectConfirmationData{correlation} Recipient=\"{}\" \
         NotOnOrAfter=\"{}\"/></saml:SubjectConfirmation></saml:Subject>\
         <saml:Conditions NotBefore=\"2025-12-31T23:58:00Z\" NotOnOrAfter=\"{}\">\
         <saml:AudienceRestriction><saml:Audience>{}</saml:Audience>\
         </saml:AudienceRestriction></saml:Conditions>\
         <saml:AttributeStatement><saml:Attribute Name=\"{EMAIL_CLAIM}\">\
         <saml:AttributeValue>ada@globex.example</saml:AttributeValue></saml:Attribute>\
         {duplicate}{encrypted}</saml:AttributeStatement>",
        body.name_id_format,
        body.recipient,
        body.not_on_or_after,
        body.not_on_or_after,
        body.audience,
    );
    ironauth_saml::test_util::signed_response_with(key, assertion_id, &children)
}

/// [`signed_body`] with everything at its default, varying only the correlation.
fn signed(key: &XmlTestKey, assertion_id: &str, in_response_to: Option<&'static str>) -> String {
    signed_body(
        key,
        assertion_id,
        &Body {
            in_response_to,
            ..Body::default()
        },
    )
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

    let now = now_micros(&env);
    replay
        .issue_request(
            &fixture.connection.id,
            "_req_audience",
            Some("/dashboard"),
            now,
            now + 300_000_000,
        )
        .await
        .expect("issue");

    // SIGNED WITH THE WRONG AUDIENCE IN IT, not edited afterwards. `saml:Audience` is inside the
    // digest, so a `.replace` on the signed bytes only ever produces a signature failure -- and
    // a test accepting `Signature(_) | Condition(_)` would pass on the wrong arm while the
    // audience comparison was never executed.
    let elsewhere = signed_body(
        &fixture.key,
        "_assertion_elsewhere",
        &Body {
            audience: "https://someone-else.example/saml/metadata",
            in_response_to: Some("_req_audience"),
            ..Body::default()
        },
    );
    let refused = consume(&replay, &fixture.acs(), elsewhere.as_bytes()).await;
    let Err(AcsError::Condition(ConditionError::WrongAudience { found })) = refused else {
        panic!("an assertion for another service provider was consumed: {refused:?}");
    };
    // WHAT WAS COMPARED, not merely that something refused: the audience the document carried
    // comes back, so a refusal arriving for any other reason would not satisfy this.
    assert_eq!(
        found.as_deref(),
        Some("https://someone-else.example/saml/metadata")
    );

    // AND THE REQUEST IT NAMED IS UNSPENT, which is the property `examine`-then-spend exists
    // for, now measured on a refusal PAST the signature. Without this the ordering was tested
    // only against a forged signature, and moving `check` after the store writes passed.
    let genuine = signed(
        &fixture.key,
        "_assertion_after_audience",
        Some("_req_audience"),
    );
    let consumed = consume(&replay, &fixture.acs(), genuine.as_bytes())
        .await
        .expect("the request the refused response named is still outstanding");
    assert_eq!(consumed.relay_state.as_deref(), Some("/dashboard"));
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

#[tokio::test]
async fn an_unreadable_attribute_statement_is_refused_and_spends_nothing() {
    // THE SECOND HALF OF THE ORDERING PROPERTY. `attributes` runs after `check` and before any
    // store write, so a document that verifies, satisfies every condition, and THEN cannot be
    // read must still leave the request outstanding. A mutation moving `attributes` past the
    // spends fails here.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let fixture = fixture(&db, &env, false).await;
    let replay = db.store().scoped(fixture.scope).saml_replay();
    let now = now_micros(&env);
    replay
        .issue_request(
            &fixture.connection.id,
            "_req_attributes",
            Some("/reports"),
            now,
            now + 300_000_000,
        )
        .await
        .expect("issue");

    // TWO ATTRIBUTES WITH ONE NAME, which `attributes` refuses rather than picking one of.
    let ambiguous = signed_body(
        &fixture.key,
        "_assertion_ambiguous",
        &Body {
            in_response_to: Some("_req_attributes"),
            duplicate_attribute: true,
            ..Body::default()
        },
    );
    let refused = consume(&replay, &fixture.acs(), ambiguous.as_bytes()).await;
    assert!(
        matches!(
            refused,
            Err(AcsError::Attributes(Unreadable::Duplicate { .. }))
        ),
        "an ambiguous attribute statement was consumed: {refused:?}"
    );

    let genuine = signed(
        &fixture.key,
        "_assertion_after_attributes",
        Some("_req_attributes"),
    );
    let consumed = consume(&replay, &fixture.acs(), genuine.as_bytes())
        .await
        .expect("the request the refused response named is still outstanding");
    assert_eq!(consumed.relay_state.as_deref(), Some("/reports"));
}

#[tokio::test]
async fn a_nameid_in_another_format_than_the_connection_expects_is_refused() {
    // A CONNECTION COLUMN THAT CONFIGURED NOTHING until this: `nameid_format` was read from the
    // row and never compared. The format is part of the identity -- `transient` names somebody
    // for one session and `persistent` names them forever -- so a connection set to one and
    // handed the other is being asked to key an account on a value it did not agree to.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let fixture = fixture(&db, &env, true).await;
    let replay = db.store().scoped(fixture.scope).saml_replay();

    let transient = signed_body(
        &fixture.key,
        "_assertion_transient",
        &Body {
            name_id_format: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
            ..Body::default()
        },
    );
    let refused = consume(&replay, &fixture.acs(), transient.as_bytes()).await;
    let Err(AcsError::WrongNameIdFormat { expected, found }) = refused else {
        panic!("a NameID in another format was consumed: {refused:?}");
    };
    assert_eq!(expected, NAMEID_FORMAT);
    assert_eq!(
        found.as_deref(),
        Some("urn:oasis:names:tc:SAML:2.0:nameid-format:transient")
    );

    // AND THE CONNECTION'S OWN FORMAT STILL PASSES, so the check is not refusing everything.
    let matching = signed(&fixture.key, "_assertion_matching_format", None);
    consume(&replay, &fixture.acs(), matching.as_bytes())
        .await
        .expect("a NameID in the configured format is admitted");
}

#[tokio::test]
async fn a_connection_requiring_encryption_refuses_a_cleartext_assertion() {
    // THE OTHER DEAD COLUMN. This build does not decrypt in this pipeline, so the honest answer
    // to `require_encrypted_assertion` is a refusal that names the limitation -- not signing
    // somebody in from a cleartext assertion on a connection whose operator asked for the
    // opposite, which is what reading the column and ignoring it did.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let fixture = fixture_with(
        &db,
        &env,
        Settings {
            allow_unsolicited: true,
            require_encrypted_assertion: true,
            ..Settings::default()
        },
    )
    .await;
    let replay = db.store().scoped(fixture.scope).saml_replay();

    // OTHERWISE PERFECT: signed by the pinned key, right audience, right recipient, in date.
    let cleartext = signed(&fixture.key, "_assertion_cleartext", None);
    let refused = consume(&replay, &fixture.acs(), cleartext.as_bytes()).await;
    assert!(
        matches!(refused, Err(AcsError::EncryptionRequired)),
        "a cleartext assertion was consumed on a connection requiring encryption: {refused:?}"
    );
}

#[tokio::test]
async fn an_encrypted_attribute_is_refused_rather_than_silently_dropped() {
    // THE READER COUNTS, THE ENDPOINT DECIDES. `ironauth-saml` passes an `EncryptedAttribute`
    // over and reports how many, because refusing there would discard a conformant assertion's
    // cleartext attributes too. That leaves somebody to act on the count, and if nobody does,
    // the assertion signs a user in with a trait the operator configured silently missing --
    // which for a group membership is the wrong authorization, not a cosmetic gap.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let fixture = fixture(&db, &env, true).await;
    let replay = db.store().scoped(fixture.scope).saml_replay();

    let with_encrypted = signed_body(
        &fixture.key,
        "_assertion_encrypted_attribute",
        &Body {
            encrypted_attribute: true,
            ..Body::default()
        },
    );
    let refused = consume(&replay, &fixture.acs(), with_encrypted.as_bytes()).await;
    assert!(
        matches!(refused, Err(AcsError::EncryptedAttributes { count: 1 })),
        "an assertion with an unreadable attribute signed somebody in: {refused:?}"
    );

    // AND THE SAME DOCUMENT WITHOUT IT IS ADMITTED, so this is the encrypted element being
    // refused and not the fixture being broken in some other way.
    let cleartext = signed(&fixture.key, "_assertion_cleartext_only", None);
    consume(&replay, &fixture.acs(), cleartext.as_bytes())
        .await
        .expect("an assertion with only cleartext attributes is admitted");
}
