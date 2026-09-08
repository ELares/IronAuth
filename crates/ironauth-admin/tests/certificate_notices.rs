// SPDX-License-Identifier: MIT OR Apache-2.0

//! Turning a recorded expiry notice into mail for the right people (issue #141).
//!
//! # What this owes
//!
//! The sweep decides an organization must be told; this decides WHO, and gets it wrong in two
//! directions that both matter. Telling nobody is the feature not working. Telling the wrong
//! people is worse than useless: an operational alert that reaches contacts who cannot act on it
//! is the alert that gets filtered, taking the ones that matter with it.

#![cfg(feature = "testing")]

use ironauth_admin::certificate_notices::{CertificateNoticeConsumer, NOTICE_KIND};
use ironauth_env::Env;
use ironauth_store::message_rate::RateBudget;
use ironauth_store::outbox::OutboxConsumer;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CERTIFICATE_NOTICE_CONSUMER, CorrelationId, MessageId, NewOrgContact, NewSamlCertificate,
    NewSamlConnection, OrgContactId, OrganizationId, SamlCertificateId, SamlConnectionId,
    SamlKeyKind, Scope,
};
use serde_json::json;
use sqlx::Row as _;

const DAY: i64 = 24 * 60 * 60;

fn p256_point(seed: u8) -> Vec<u8> {
    let mut point = vec![0x04];
    point.extend(std::iter::repeat_n(seed, 64));
    point
}

fn fingerprint(seed: u8) -> Vec<u8> {
    std::iter::repeat_n(seed, 32).collect()
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

async fn seed_org(db: &TestDatabase, env: &Env, scope: Scope, name: &str) -> OrganizationId {
    let id = OrganizationId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .organizations(scope)
        .create(env, &id, now_micros(env), name, None)
        .await
        .expect("create organization");
    id
}

async fn connect(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    organization: &OrganizationId,
    idp_entity_id: &str,
) -> SamlConnectionId {
    let id = SamlConnectionId::generate(env, &scope);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .saml_connections()
        .create(
            env,
            NewSamlConnection {
                id: &id,
                organization_id: organization,
                display_name: "Okta",
                idp_entity_id,
                idp_sso_url: "https://idp.example/sso",
                sp_entity_id: "https://ironauth.example/saml/metadata",
                acs_url: "https://ironauth.example/saml/acs",
                allow_unsolicited: false,
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
        .expect("create the SAML connection");
    id
}

async fn pin_expiring(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    connection: &SamlConnectionId,
    seed: u8,
    in_secs: i64,
) -> SamlCertificateId {
    let id = SamlCertificateId::generate(env, &scope);
    let now = now_micros(env);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .saml_connections()
        .pin_certificate(
            env,
            NewSamlCertificate {
                id: &id,
                connection_id: connection,
                key_kind: SamlKeyKind::EcdsaP256,
                public_key: &p256_point(seed),
                rsa_exponent: None,
                certificate_der: &[0x30, 0x82, seed],
                fingerprint_sha256: &fingerprint(seed),
                not_before_unix_micros: now + (in_secs - 365 * DAY) * 1_000_000,
                not_after_unix_micros: now + in_secs * 1_000_000,
            },
            None,
            None,
        )
        .await
        .expect("pin the certificate");
    id
}
async fn add_contact(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    organization: &OrganizationId,
    email: &str,
    category: &str,
) -> OrgContactId {
    let id = OrgContactId::generate(env, &scope);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .org_contacts()
        .add(
            env,
            NewOrgContact {
                id: &id,
                organization_id: organization,
                display_name: "A Person",
                email,
                category,
                created_at_micros: now_micros(env),
            },
        )
        .await
        .expect("add the contact");
    id
}

fn budget() -> RateBudget {
    RateBudget::new(100, 3600)
}

/// Run the notice consumer over everything the sweep queued for it, LOOPING to empty.
///
/// One claim is not a drain: the outbox serialises per ordering key and every notice about one
/// certificate shares its id as their subject, so the second is not claimable until the first is
/// completed. Reading one claim as "the sweep queued one notice" is a mistake this suite's
/// sibling already made.
async fn drain_notices(db: &TestDatabase, env: &Env, scope: Scope, page: i64) -> usize {
    let consumer = CertificateNoticeConsumer::with_page_size(db.store().clone(), budget(), page);
    let mut handled = 0;
    loop {
        let claimed = db
            .store()
            .scoped(scope)
            .outbox()
            .claim(
                env,
                CERTIFICATE_NOTICE_CONSUMER,
                std::time::Duration::from_secs(30),
                100,
            )
            .await
            .expect("claim");
        if claimed.is_empty() {
            return handled;
        }
        for message in claimed {
            consumer
                .handle(env, scope, &message)
                .await
                .expect("the notice is handled");
            db.store()
                .scoped(scope)
                .outbox()
                .complete(env, &message)
                .await
                .expect("complete");
            handled += 1;
        }
    }
}

/// Every address the expiry notices actually reached, opened from the seal.
async fn notified(db: &TestDatabase, scope: Scope) -> Vec<String> {
    let rows = sqlx::query(
        "SELECT id FROM messages WHERE tenant_id = $1 AND environment_id = $2 AND kind = $3 \
         ORDER BY created_at, id",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(NOTICE_KIND)
    .fetch_all(db.owner_pool())
    .await
    .expect("read the messages");
    let mut out = Vec::new();
    for row in &rows {
        let raw: String = row.get("id");
        let id = MessageId::parse_in_scope(&raw, &scope).expect("a message id");
        out.push(
            db.store()
                .scoped(scope)
                .messages()
                .open_recipient(&id)
                .await
                .expect("open the recipient")
                .expect("a recipient"),
        );
    }
    out.sort();
    out
}

#[tokio::test]
async fn a_notice_reaches_the_technical_contacts_and_nobody_else() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = seed_org(&db, &env, scope, "Contoso").await;
    add_contact(&db, &env, scope, &org, "ops@contoso.test", "technical").await;
    add_contact(&db, &env, scope, &org, "soc@contoso.test", "security").await;
    add_contact(&db, &env, scope, &org, "ap@contoso.test", "billing").await;
    let connection = connect(&db, &env, scope, &org, "https://idp.example/e").await;
    pin_expiring(&db, &env, scope, &connection, 7, 2 * DAY).await;

    let report = ironauth_admin::certificate_expiry::run_once(
        db.control_store(),
        &env,
        scope,
        &[3 * DAY],
        100,
    )
    .await
    .expect("the sweep runs");
    assert_eq!(report.announced, 1, "one certificate, one crossed lead");

    assert_eq!(drain_notices(&db, &env, scope, 100).await, 1, "one notice");
    assert_eq!(
        notified(&db, scope).await,
        vec!["ops@contoso.test".to_owned()],
        "the technical contact is told; the security and billing contacts are not, because \
         replacing an IdP certificate is not work either of them can do"
    );
}

#[tokio::test]
async fn a_technical_contact_past_the_first_page_is_still_told() {
    // THE PAGING LOOP, with the boundary lowered to one so two rows prove it. Reading one page
    // and stopping is a defect this codebase shipped once already, on the delete path for these
    // same contacts, where it silently mis-categorised the removal event.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = seed_org(&db, &env, scope, "Contoso").await;
    add_contact(&db, &env, scope, &org, "first@contoso.test", "technical").await;
    add_contact(&db, &env, scope, &org, "second@contoso.test", "technical").await;
    let connection = connect(&db, &env, scope, &org, "https://idp.example/e").await;
    pin_expiring(&db, &env, scope, &connection, 7, 2 * DAY).await;

    ironauth_admin::certificate_expiry::run_once(db.control_store(), &env, scope, &[3 * DAY], 100)
        .await
        .expect("the sweep runs");
    drain_notices(&db, &env, scope, 1).await;

    assert_eq!(
        notified(&db, scope).await,
        vec![
            "first@contoso.test".to_owned(),
            "second@contoso.test".to_owned()
        ],
        "both contacts are told, including the one past the page boundary"
    );
}

#[tokio::test]
async fn another_organizations_contacts_are_not_told() {
    // The contact list is the notification BOUNDARY, and a certificate belongs to exactly one
    // organization. Telling a neighbour's IT admin about this one leaks that the organization
    // uses SSO, when it expires, and which connection it is.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let expiring = seed_org(&db, &env, scope, "Contoso").await;
    let bystander = seed_org(&db, &env, scope, "Initech").await;
    add_contact(&db, &env, scope, &expiring, "ops@contoso.test", "technical").await;
    add_contact(
        &db,
        &env,
        scope,
        &bystander,
        "ops@initech.test",
        "technical",
    )
    .await;
    let connection = connect(&db, &env, scope, &expiring, "https://idp.example/e").await;
    pin_expiring(&db, &env, scope, &connection, 7, 2 * DAY).await;

    ironauth_admin::certificate_expiry::run_once(db.control_store(), &env, scope, &[3 * DAY], 100)
        .await
        .expect("the sweep runs");
    drain_notices(&db, &env, scope, 100).await;

    assert_eq!(
        notified(&db, scope).await,
        vec!["ops@contoso.test".to_owned()],
        "only the owning organization's contact is told"
    );
}

#[tokio::test]
async fn an_organization_with_no_contacts_completes_rather_than_dead_lettering() {
    // Nobody listed is the state every organization is in before anyone sets contacts up. If
    // that dead-lettered, an operator's queue would fill with work nobody can act on, and the
    // real failures would be lost in it.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = seed_org(&db, &env, scope, "Contoso").await;
    let connection = connect(&db, &env, scope, &org, "https://idp.example/e").await;
    pin_expiring(&db, &env, scope, &connection, 7, 2 * DAY).await;

    ironauth_admin::certificate_expiry::run_once(db.control_store(), &env, scope, &[3 * DAY], 100)
        .await
        .expect("the sweep runs");

    assert_eq!(
        drain_notices(&db, &env, scope, 100).await,
        1,
        "the notice is handled and completed, not raised"
    );
    assert!(
        notified(&db, scope).await.is_empty(),
        "there was nobody to tell"
    );
}

#[tokio::test]
async fn each_crossed_lead_is_its_own_mail() {
    // Two leads crossing at once are two DIFFERENT things to say -- "renew this month" and
    // "renew today" -- so the collapse window is keyed on the lead. A shared window would let
    // the urgent one be swallowed by the one already sent.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = seed_org(&db, &env, scope, "Contoso").await;
    add_contact(&db, &env, scope, &org, "ops@contoso.test", "technical").await;
    let connection = connect(&db, &env, scope, &org, "https://idp.example/e").await;
    pin_expiring(&db, &env, scope, &connection, 7, 2 * DAY).await;

    let report = ironauth_admin::certificate_expiry::run_once(
        db.control_store(),
        &env,
        scope,
        &[30 * DAY, 3 * DAY],
        100,
    )
    .await
    .expect("the sweep runs");
    assert_eq!(report.announced, 2, "both leads have been crossed");

    assert_eq!(drain_notices(&db, &env, scope, 100).await, 2, "two notices");
    assert_eq!(
        notified(&db, scope).await,
        vec!["ops@contoso.test".to_owned(), "ops@contoso.test".to_owned()],
        "the same person is mailed once per lead, not once in total"
    );
}

#[tokio::test]
async fn two_certificates_crossing_the_same_lead_are_two_mails() {
    // THE COLLAPSE MUST KEY ON THE CERTIFICATE. An organization with two SAML connections --
    // one per IdP, which is ordinary for a company mid-migration -- can have both certificates
    // cross the same threshold on the same day. The first version of this consumer keyed the
    // collapse on the lead alone, so the second notice hashed identically to the first and was
    // silently dropped: the customer was warned about one connection and never about the other,
    // which is precisely the failure the whole feature exists to prevent.
    //
    // It passed every other test in this file, because every other test varies the lead.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = seed_org(&db, &env, scope, "Contoso").await;
    add_contact(&db, &env, scope, &org, "ops@contoso.test", "technical").await;
    let okta = connect(&db, &env, scope, &org, "https://okta.example/e").await;
    let entra = connect(&db, &env, scope, &org, "https://entra.example/e").await;
    pin_expiring(&db, &env, scope, &okta, 7, 2 * DAY).await;
    pin_expiring(&db, &env, scope, &entra, 9, 2 * DAY).await;

    let report = ironauth_admin::certificate_expiry::run_once(
        db.control_store(),
        &env,
        scope,
        &[3 * DAY],
        100,
    )
    .await
    .expect("the sweep runs");
    assert_eq!(report.announced, 2, "both certificates have crossed");

    assert_eq!(drain_notices(&db, &env, scope, 100).await, 2, "two notices");
    assert_eq!(
        notified(&db, scope).await,
        vec!["ops@contoso.test".to_owned(), "ops@contoso.test".to_owned()],
        "the contact is told about BOTH certificates, not just whichever was announced first"
    );
}
