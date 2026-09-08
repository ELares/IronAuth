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

/// The clock the message ledger counts rate windows in.
fn now_secs(env: &Env) -> u64 {
    env.clock()
        .now_utc()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs()
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

/// The BODIES queued for delivery, in order.
///
/// The rendered text does not live on the `messages` row; it rides the delivery job's outbox
/// payload, which is what a provider is handed. Reading it there is reading what the contact
/// will actually be sent.
async fn delivered_bodies(db: &TestDatabase, env: &Env, scope: Scope) -> Vec<String> {
    // LOOPING, for the reason `drain_notices` loops: the delivery queue's ordering key is the
    // RECIPIENT, so every notice to one contact shares it and the second is not claimable until
    // the first is completed. A single claim returned one body and read as "only one mail was
    // sent" -- the same mistake this suite's sibling made, one queue along.
    let mut bodies = Vec::new();
    loop {
        let claimed = db
            .store()
            .scoped(scope)
            .outbox()
            .claim(
                env,
                ironauth_store::MESSAGE_DELIVERY_CONSUMER,
                std::time::Duration::from_secs(30),
                100,
            )
            .await
            .expect("claim the deliveries");
        if claimed.is_empty() {
            return bodies;
        }
        for message in &claimed {
            bodies.push(
                message.payload["body"]
                    .as_str()
                    .expect("a rendered body")
                    .to_owned(),
            );
            db.store()
                .scoped(scope)
                .outbox()
                .complete(env, message)
                .await
                .expect("complete");
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
    // and stopping is a defect this codebase has already written once, on the delete path for
    // these same contacts, where it DROPPED the removal event rather than mislabelling it --
    // caught by mutation before merge. Dropped is what would happen here too: a contact past
    // page one is never told, while the ledger records that the organization was.
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
    // ONE CONNECTION, TWO CERTIFICATES -- the rollover state this whole feature exists to warn
    // about, an IdP publishing its replacement alongside the certificate it is retiring.
    //
    // The first version of this test used two CONNECTIONS with one certificate each, so the
    // certificate and the connection varied together and the assertion below could not say which
    // one the collapse key was on. Review demonstrated it: keying the discriminator on the
    // connection instead of the certificate left all six tests green. Varying one dimension is
    // what makes this a negative for the certificate specifically.
    let connection = connect(&db, &env, scope, &org, "https://okta.example/e").await;
    pin_expiring(&db, &env, scope, &connection, 7, 2 * DAY).await;
    pin_expiring(&db, &env, scope, &connection, 9, 2 * DAY).await;

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

#[tokio::test]
async fn the_mail_states_the_time_actually_left_and_not_the_lead_it_crossed() {
    // WHAT THE CONTACT READS, which nothing measured. The body was the only part of this
    // feature no test observed, and it was wrong: it formatted the LEAD that was crossed rather
    // than the time remaining, and the two are equal only at the instant of crossing.
    //
    // The case that exposes it is the ordinary one for an existing deployment switching alerting
    // on: a certificate already deep inside its windows crosses every lead at once. Two days
    // from expiry, the thirty-day notice said "expires in about 30 days" -- understating the
    // urgency by four weeks and contradicting the other two notices about the same certificate.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = seed_org(&db, &env, scope, "Contoso").await;
    add_contact(&db, &env, scope, &org, "ops@contoso.test", "technical").await;
    let connection = connect(&db, &env, scope, &org, "https://idp.example/e").await;
    pin_expiring(&db, &env, scope, &connection, 7, 2 * DAY).await;

    ironauth_admin::certificate_expiry::run_once(
        db.control_store(),
        &env,
        scope,
        &[30 * DAY, 14 * DAY, 3 * DAY],
        100,
    )
    .await
    .expect("the sweep runs");
    drain_notices(&db, &env, scope, 100).await;

    let bodies = delivered_bodies(&db, &env, scope).await;
    assert_eq!(bodies.len(), 3, "one mail per crossed lead");
    for body in &bodies {
        assert!(
            body.contains(&connection.to_string()),
            "the mail must name the connection whose certificate is expiring: {body}"
        );
        // TWO DAYS, in every one of the three. Under the old body these read "30", "14" and "3".
        assert!(
            body.contains("expires in about 2 days"),
            "the mail must state the time actually remaining, not the lead: {body}"
        );
    }
}

#[tokio::test]
async fn a_notice_that_outlives_its_certificate_says_it_has_expired() {
    // CLOCK-CONTROLLED, and the clock is the point. `due()` refuses a certificate that has
    // already lapsed (`not_after > now`), so a sweep never announces one -- which is why an
    // earlier version of this test, driving the sweep against a lapsed certificate, announced
    // nothing and proved nothing.
    //
    // The way production reaches an expired body is the DELAY: the notice is announced while the
    // certificate is still valid, then sits in the queue -- retries, a backlog, a worker that
    // was down -- past the expiry it was warning about. Then "expires in about 0 days" reads as
    // a rounding artifact when the organization's logins are already failing.
    // A FIXED START, not the wall clock. `invariant-lints` requires every clock to come from
    // ironauth-env so protocol logic stays deterministic under test, and it enforces that by
    // scanning source text -- which is why this comment describes the rule rather than quoting
    // the call it forbids. 2026-01-01T00:00:00Z, far enough forward that a certificate's
    // `not_before` (a year before its expiry) is still a sane timestamp.
    let (env, clock) = Env::deterministic(
        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_767_225_600),
        31,
    );
    let db = TestDatabase::start().await;
    let scope = db.seed_scope(&env).await;

    let org = seed_org(&db, &env, scope, "Contoso").await;
    add_contact(&db, &env, scope, &org, "ops@contoso.test", "technical").await;
    let connection = connect(&db, &env, scope, &org, "https://idp.example/e").await;
    pin_expiring(&db, &env, scope, &connection, 7, 2 * DAY).await;

    ironauth_admin::certificate_expiry::run_once(db.control_store(), &env, scope, &[3 * DAY], 100)
        .await
        .expect("the sweep runs");

    // The notice is queued and the certificate lapses underneath it.
    clock.advance(std::time::Duration::from_secs(
        u64::try_from(3 * DAY).expect("positive"),
    ));
    drain_notices(&db, &env, scope, 100).await;

    let bodies = delivered_bodies(&db, &env, scope).await;
    assert_eq!(bodies.len(), 1);
    assert!(
        bodies[0].contains("HAS EXPIRED"),
        "a notice delivered after the expiry it warned about must say so: {}",
        bodies[0]
    );
    assert!(
        !bodies[0].contains("expires in about"),
        "and must not also count down: {}",
        bodies[0]
    );
}

#[tokio::test]
async fn a_rate_limited_notice_is_retried_rather_than_silently_dropped() {
    // THE DEFECT THIS TEST EXISTS FOR, which review found by running the SHIPPED budget instead
    // of the generous one every test here supplied. Completing a message the rate limiter
    // refused loses the notice permanently: the ledger row recording that this organization was
    // told has already committed, so no later sweep re-announces it, and the outbox row would be
    // marked done. Measured on the old budget, an organization with two connections and the
    // three default leads had six crossings announced and three mails sent.
    //
    // The rate limiter's own doc says exceeding it BLOCKS rather than delays, which is right for
    // a login code the user will ask for again, and wrong for a notice nothing re-requests. So
    // the consumer returns a retryable error and the outbox backs off.
    //
    // Driven with a budget of ONE so the property is measured rather than the number: whatever
    // the shipped budget is, exceeding it must delay and never drop.
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
    assert_eq!(
        report.announced, 2,
        "two leads crossed, two notices recorded"
    );

    let consumer =
        CertificateNoticeConsumer::new(db.store().clone(), RateBudget::new(1, 3_600).per_kind());
    let mut accepted = 0;
    let mut retried = 0;
    loop {
        let claimed = db
            .store()
            .scoped(scope)
            .outbox()
            .claim(
                &env,
                CERTIFICATE_NOTICE_CONSUMER,
                std::time::Duration::from_secs(30),
                100,
            )
            .await
            .expect("claim");
        if claimed.is_empty() {
            break;
        }
        for message in claimed {
            match consumer.handle(&env, scope, &message).await {
                Ok(()) => accepted += 1,
                Err(error) => {
                    assert!(
                        error.is_retryable(),
                        "a rate-limited notice must be RETRYABLE, not dead-lettered on the spot"
                    );
                    assert_eq!(error.label(), "notice_rate_limited", "and say why");
                    retried += 1;
                }
            }
            // Completed either way here, because this test is about what `handle` ANSWERS. In
            // production the substrate completes only the Ok and reschedules the Err.
            db.store()
                .scoped(scope)
                .outbox()
                .complete(&env, &message)
                .await
                .expect("complete");
        }
    }

    assert_eq!(accepted, 1, "the budget of one admits exactly one notice");
    assert_eq!(
        retried, 1,
        "and the notice beyond it is handed back for retry rather than reported as sent"
    );
    assert_eq!(
        notified(&db, scope).await,
        vec!["ops@contoso.test".to_owned()],
        "only the admitted notice produced mail; the other was not silently written off"
    );
}

#[tokio::test]
async fn a_rate_limited_contact_does_not_block_the_contacts_after_them() {
    // The first version of the retry returned at the FIRST refused contact, which is a delay
    // every later contact on the list did nothing to earn: they would go unmailed until one
    // other recipient's window rolled. Every contact is tried, and the retry is raised after.
    //
    // The budget is per recipient, so this needs one contact who has already spent theirs.
    // Enqueuing a notice-kind message to them directly is exactly that state.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = seed_org(&db, &env, scope, "Contoso").await;
    // Added first, so the contact list reaches this one first: the property is about what
    // happens to the contacts AFTER a refusal.
    add_contact(&db, &env, scope, &org, "spent@contoso.test", "technical").await;
    add_contact(&db, &env, scope, &org, "fresh@contoso.test", "technical").await;
    let connection = connect(&db, &env, scope, &org, "https://idp.example/e").await;
    pin_expiring(&db, &env, scope, &connection, 7, 2 * DAY).await;

    // Spend the first contact's whole budget on an unrelated notice-kind send.
    let spent_id = MessageId::generate(&env, &scope);
    db.store()
        .scoped(scope)
        .messages()
        .enqueue(
            &env,
            ironauth_store::NewMessage {
                id: &spent_id,
                kind: NOTICE_KIND,
                recipient: "spent@contoso.test",
                dedup_key: "an-earlier-unrelated-notice",
            },
            &serde_json::json!({ "message_id": spent_id.to_string(), "body": "earlier" }),
            RateBudget::new(1, 3_600).per_kind(),
            // THE SAME WINDOW the consumer will count in. Passing 0 here put the earlier send in
            // the window that began at the Unix epoch, so it counted against nothing and the
            // contact was not spent at all -- the setup silently did not set anything up.
            now_secs(&env),
        )
        .await
        .expect("the earlier send is accepted");

    ironauth_admin::certificate_expiry::run_once(db.control_store(), &env, scope, &[3 * DAY], 100)
        .await
        .expect("the sweep runs");

    let consumer =
        CertificateNoticeConsumer::new(db.store().clone(), RateBudget::new(1, 3_600).per_kind());
    let claimed = db
        .store()
        .scoped(scope)
        .outbox()
        .claim(
            &env,
            CERTIFICATE_NOTICE_CONSUMER,
            std::time::Duration::from_secs(30),
            10,
        )
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 1, "one notice");
    let outcome = consumer.handle(&env, scope, &claimed[0]).await;

    assert!(
        outcome.is_err(),
        "the refused contact must still be handed back for retry"
    );
    let reached = notified(&db, scope).await;
    assert!(
        reached.contains(&"fresh@contoso.test".to_owned()),
        "the contact after the refused one must still have been mailed in this same pass: \
         {reached:?}"
    );
}

#[tokio::test]
async fn hours_left_is_said_as_less_than_a_day_rather_than_rounded() {
    // The sub-day branch was added as part of fixing the rounding and then measured by nothing:
    // deleting it left every test green. Any rounding of a few hours into a whole number of days
    // is off by up to twelve hours, and this is the one range where that decides whether
    // somebody acts tonight.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = seed_org(&db, &env, scope, "Contoso").await;
    add_contact(&db, &env, scope, &org, "ops@contoso.test", "technical").await;
    let connection = connect(&db, &env, scope, &org, "https://idp.example/e").await;
    pin_expiring(&db, &env, scope, &connection, 7, 12 * 60 * 60).await;

    ironauth_admin::certificate_expiry::run_once(db.control_store(), &env, scope, &[3 * DAY], 100)
        .await
        .expect("the sweep runs");
    drain_notices(&db, &env, scope, 100).await;

    let bodies = delivered_bodies(&db, &env, scope).await;
    assert_eq!(bodies.len(), 1);
    assert!(
        bodies[0].contains("LESS THAN A DAY"),
        "twelve hours must not be reported as a whole number of days: {}",
        bodies[0]
    );
}
