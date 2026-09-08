// SPDX-License-Identifier: MIT OR Apache-2.0

//! Certificate expiry alerting: which notices are due, and which have already gone out
//! (issue #141), over a real database (`DATABASE_URL`).
//!
//! # The failure this exists to prevent
//!
//! #141 opens by naming it: certificate rot is the number one silent killer of SAML connections.
//! The identity provider's signing certificate expires, logins break for an entire enterprise
//! customer, and the vendor learns about it from an angry ticket. The fix is telling somebody
//! early enough to act, at each of several lead times, which makes the interesting questions
//! here about COUNTING rather than about correctness of a single answer: exactly one notice per
//! threshold, never a second, and never a notice about a certificate that has already died.
//!
//! # Why the lead is part of the key
//!
//! A "last alerted at" column would make the thirty-day and fourteen-day notices one fact.
//! Crossing fourteen days would then either be suppressed by the thirty-day row or would
//! overwrite it and let the thirty-day notice fire again on the next pass. Each threshold is a
//! separate promise to the customer and gets a separate row, which is what lets a sweep cross
//! several at once and send one notice for each.

#![cfg(feature = "testing")]

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, NewSamlCertificate, NewSamlConnection, OrganizationId, SamlCertificateId,
    SamlConnectionId, SamlKeyKind, Scope, StoreError,
};
use serde_json::json;

const DAY: i64 = 24 * 60 * 60;
/// The leads #141 names: thirty days, fourteen, three.
const LEADS: &[i64] = &[30 * DAY, 14 * DAY, 3 * DAY];

/// A P-256 uncompressed point: `0x04` and 64 bytes. Not a real key, and it does not need to be:
/// what these tests exercise is the STORE, and the verifier has its own suite for key material.
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

/// A connection with everything at its default, returning the handle.
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

/// Pin a P-256 key whose `not_after` is exactly `at_micros`, returning the handle.
///
/// EXISTS SO A FIXTURE CAN SIT ON A BOUNDARY. `pin_expiring` computes the expiry from its OWN
/// clock reading, which is microseconds later than the caller's `now`, so a certificate meant to
/// land exactly on `now + lead` lands just past it and the comparison at the boundary is never
/// the one being driven.
async fn pin_at(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    connection: &SamlConnectionId,
    seed: u8,
    at_micros: i64,
) -> SamlCertificateId {
    let id = SamlCertificateId::generate(env, &scope);
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
                not_before_unix_micros: at_micros - 365 * DAY * 1_000_000,
                not_after_unix_micros: at_micros,
            },
            None,
            None,
        )
        .await
        .expect("pin the certificate");
    id
}

/// Pin a P-256 key expiring `in_secs` from now, returning the handle.
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
                // A YEAR BEFORE IT EXPIRES, rather than a second ago: the schema requires
                // `not_before < not_after`, so an already-expired fixture cannot take a
                // just-now start. Real certificates have a validity SPAN, and the expired case
                // is the one this file most needs to be able to build.
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

#[tokio::test]
async fn a_certificate_is_due_for_every_lead_it_has_crossed_and_no_others() {
    // THE SHAPE THAT MATTERS: a sweep that has not run for a while crosses several thresholds at
    // once, and each is a separate notice. Collapsing them to "the nearest lead" would mean a
    // customer who was never told at thirty days is told only at three, which is exactly the
    // outage #141 is about -- three days is not enough to get an identity provider change
    // through a change-management process.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &org, "https://idp.example/a").await;
    let now = now_micros(&env);
    let alerts = db.control_store().scoped(scope).saml_certificate_alerts();

    // Inside the 3-day lead, so inside all three.
    let soon = pin_expiring(&db, &env, scope, &connection, 1, 2 * DAY).await;
    let due = alerts.due(now, LEADS, 100).await.expect("due");
    let leads: Vec<i64> = due
        .iter()
        .filter(|entry| entry.certificate_id == soon.to_string())
        .map(|entry| entry.lead_secs)
        .collect();
    assert_eq!(
        leads,
        vec![3 * DAY, 14 * DAY, 30 * DAY],
        "a certificate two days out is due for every lead it has crossed: {due:?}"
    );

    // Inside 30 but outside 14: one lead only.
    let later = pin_expiring(&db, &env, scope, &connection, 2, 20 * DAY).await;
    let due = alerts.due(now, LEADS, 100).await.expect("due");
    let leads: Vec<i64> = due
        .iter()
        .filter(|entry| entry.certificate_id == later.to_string())
        .map(|entry| entry.lead_secs)
        .collect();
    assert_eq!(
        leads,
        vec![30 * DAY],
        "a certificate twenty days out crossed only the thirty-day lead: {due:?}"
    );

    // Outside every lead: not due at all.
    let far = pin_expiring(&db, &env, scope, &connection, 3, 90 * DAY).await;
    let due = alerts.due(now, LEADS, 100).await.expect("due");
    assert!(
        !due.iter()
            .any(|entry| entry.certificate_id == far.to_string()),
        "a certificate ninety days out is not due for anything: {due:?}"
    );
}

#[tokio::test]
async fn an_expired_certificate_is_not_due_for_a_warning() {
    // A NOTICE SAYING "EXPIRES IN THREE DAYS" ABOUT A CERTIFICATE THAT DIED LAST WEEK IS WORSE
    // THAN SILENCE: it tells an operator the wrong thing about how much time they have, and the
    // connection is already broken by then. Expiry is a different event and belongs to
    // connection health rather than to the warning ladder.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &org, "https://idp.example/b").await;
    let now = now_micros(&env);
    let alerts = db.control_store().scoped(scope).saml_certificate_alerts();

    let dead = pin_expiring(&db, &env, scope, &connection, 4, -DAY).await;
    let due = alerts.due(now, LEADS, 100).await.expect("due");
    assert!(
        !due.iter()
            .any(|entry| entry.certificate_id == dead.to_string()),
        "an already-expired certificate was queued for an expiry WARNING: {due:?}"
    );

    // THE CONTROL: one second before it dies, it is still due -- so the rule above is a bound at
    // expiry and not a filter that refuses everything.
    let alive = pin_expiring(&db, &env, scope, &connection, 5, 1).await;
    let due = alerts.due(now, LEADS, 100).await.expect("due");
    assert!(
        due.iter()
            .any(|entry| entry.certificate_id == alive.to_string()),
        "a certificate one second from expiry is not due, so the bound is in the wrong place: \
         {due:?}"
    );
}

#[tokio::test]
async fn a_recorded_notice_is_not_due_again_and_its_siblings_still_are() {
    // ONE NOTICE PER THRESHOLD, WHICH IS THE WHOLE POINT OF THE LEDGER. A sweep that re-sent the
    // thirty-day warning every pass would be filtered into a folder nobody reads, and the
    // fourteen-day one would arrive there too.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &org, "https://idp.example/c").await;
    let now = now_micros(&env);
    let alerts = db.control_store().scoped(scope).saml_certificate_alerts();
    let certificate = pin_expiring(&db, &env, scope, &connection, 6, 2 * DAY).await;

    alerts
        .record_sent(&env, &certificate, 30 * DAY, now, None)
        .await
        .expect("record the thirty-day notice");

    let due = alerts.due(now, LEADS, 100).await.expect("due");
    let leads: Vec<i64> = due.iter().map(|entry| entry.lead_secs).collect();
    assert_eq!(
        leads,
        vec![3 * DAY, 14 * DAY],
        "recording one lead did not remove exactly that lead: {due:?}"
    );

    // AND A SECOND ATTEMPT AT THE SAME PAIR IS REFUSED, which is what makes two sweeps racing
    // over one certificate send exactly one notice between them: the insert is the check, so the
    // loser finds out inside its own transaction rather than after delivering.
    let again = alerts
        .record_sent(&env, &certificate, 30 * DAY, now + 1, None)
        .await;
    assert!(
        matches!(again, Err(StoreError::Conflict)),
        "a second send of one threshold was not refused: {again:?}"
    );
}

#[tokio::test]
async fn a_lead_nobody_configured_is_never_looked_up() {
    // THE CONFIGURED SET CAN CHANGE, and both directions have to work. An operator who ADDS a
    // seven-day lead should get seven-day notices for certificates already inside thirty days;
    // one who REMOVES a lead should not see its rows resurface as unsent work. Keying the ledger
    // on the configured number is what makes both fall out rather than needing a migration.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &org, "https://idp.example/d").await;
    let now = now_micros(&env);
    let alerts = db.control_store().scoped(scope).saml_certificate_alerts();
    let certificate = pin_expiring(&db, &env, scope, &connection, 7, 5 * DAY).await;

    // Sent under the old set.
    alerts
        .record_sent(&env, &certificate, 14 * DAY, now, None)
        .await
        .expect("record");

    // A NEW LEAD APPEARS: the certificate is inside it and has never been announced for it.
    let widened: Vec<i64> = vec![30 * DAY, 14 * DAY, 7 * DAY, 3 * DAY];
    let due = alerts.due(now, &widened, 100).await.expect("due");
    let leads: Vec<i64> = due.iter().map(|entry| entry.lead_secs).collect();
    assert_eq!(
        leads,
        vec![7 * DAY, 30 * DAY],
        "adding a lead did not make it due, or resurrected one already sent: {due:?}"
    );

    // A LEAD IS REMOVED: its recorded row is simply never consulted, and nothing else changes.
    let narrowed: Vec<i64> = vec![3 * DAY];
    let due = alerts.due(now, &narrowed, 100).await.expect("due");
    assert!(
        due.is_empty(),
        "a five-day certificate is not inside a three-day lead: {due:?}"
    );

    // AND AN EMPTY SET ASKS NOTHING, rather than meaning "every lead".
    let due = alerts.due(now, &[], 100).await.expect("due");
    assert!(due.is_empty(), "an empty lead set returned work: {due:?}");
}

#[tokio::test]
async fn a_recorded_notice_suppresses_only_its_own_certificate() {
    // THE ANTI-JOIN NAMES THREE COLUMNS AND ONLY TWO WERE MEASURED. Every earlier test in this
    // file used ONE certificate, so `AND a.certificate_id = c.id` could be deleted and they all
    // stayed green: with a single certificate the scope columns alone already match the right
    // row. Two certificates is what tells them apart -- drop that clause and a notice sent for
    // one silences the OTHER, which is a customer never warned about a certificate nobody has
    // touched.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &org, "https://idp.example/f").await;
    let now = now_micros(&env);
    let alerts = db.control_store().scoped(scope).saml_certificate_alerts();

    let told = pin_expiring(&db, &env, scope, &connection, 20, 2 * DAY).await;
    let untold = pin_expiring(&db, &env, scope, &connection, 21, 2 * DAY).await;
    for lead in LEADS {
        alerts
            .record_sent(&env, &told, *lead, now, None)
            .await
            .expect("record every lead for the first certificate");
    }

    let due = alerts.due(now, LEADS, 100).await.expect("due");
    let certificates: Vec<&str> = due
        .iter()
        .map(|entry| entry.certificate_id.as_str())
        .collect();
    assert!(
        !certificates.contains(&told.to_string().as_str()),
        "a fully-announced certificate is still due: {due:?}"
    );
    assert_eq!(
        due.len(),
        3,
        "the untouched certificate lost notices to its neighbour's ledger rows: {due:?}"
    );
    assert!(
        certificates
            .iter()
            .all(|id| *id == untold.to_string().as_str()),
        "the due set is not exactly the untouched certificate: {due:?}"
    );
}

#[tokio::test]
async fn every_field_the_caller_is_handed_is_the_certificates_own() {
    // FIELDS THAT NOTHING READ. The tests matched on `certificate_id` and `lead_secs` and never
    // looked at the rest, so those could have been another row's and nothing would have said.
    // They are not decoration: `connection_id` names the identity provider connection an
    // operator has to go and fix, and the expiry is what the notice tells them.
    //
    // THE ORGANIZATION IS NOT ASSERTED HERE. The field a sweep will route on is `organization_id`
    // rather than `connection_id` -- neither routes today, since no sweep exists -- and this
    // would hold for any row returned.
    // `the_work_item_names_the_certificates_own_organization`
    // builds two, which is what that claim needs.
    // builds two, which is what that claim needs.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    // TWO connections, so a build that returned "a connection" rather than "this certificate's
    // connection" has something to get wrong.
    let mine = connect(&db, &env, scope, &org, "https://idp.example/g").await;
    let other = connect(&db, &env, scope, &org, "https://idp.example/h").await;
    let now = now_micros(&env);
    pin_expiring(&db, &env, scope, &other, 22, 20 * DAY).await;
    let certificate = pin_expiring(&db, &env, scope, &mine, 23, 2 * DAY).await;

    let due = db
        .control_store()
        .scoped(scope)
        .saml_certificate_alerts()
        .due(now, &[3 * DAY], 100)
        .await
        .expect("due");
    assert_eq!(
        due.len(),
        1,
        "expected exactly the two-day certificate: {due:?}"
    );
    let entry = &due[0];
    assert_eq!(entry.certificate_id, certificate.to_string());
    assert_eq!(
        entry.connection_id,
        mine.to_string(),
        "the entry names another certificate's connection, so an operator would be sent to fix \
         the wrong identity provider"
    );
    // NOT AN ORGANIZATION ASSERTION HERE. Both connections in this fixture belong to ONE
    // organization, so comparing `organization_id` against it would hold for any row the query
    // returned and would measure nothing -- the same decoy flaw this test's own comment warns
    // about. `the_work_item_names_the_certificates_own_organization` builds two organizations,
    // which is what that claim needs.
    assert_eq!(entry.lead_secs, 3 * DAY);
    // WITHIN A SECOND of what was pinned: the fixture computes the expiry from the same clock
    // reading, and the column round-trips through microseconds.
    let expected = now + 2 * DAY * 1_000_000;
    assert!(
        (entry.not_after_unix_micros - expected).abs() < 1_000_000,
        "the entry's expiry is not the certificate's: {} against {expected}",
        entry.not_after_unix_micros
    );
}

/// Every event the outbox is holding for this scope, drained.
async fn queued_events(db: &TestDatabase, env: &Env, scope: Scope) -> Vec<serde_json::Value> {
    let claimed = db
        .store()
        .scoped(scope)
        .outbox()
        .claim(
            env,
            ironauth_store::WEBHOOK_EVENT_CONSUMER,
            std::time::Duration::from_secs(30),
            100,
        )
        .await
        .expect("claim");
    for message in &claimed {
        db.store()
            .scoped(scope)
            .outbox()
            .complete(env, message)
            .await
            .expect("complete");
    }
    claimed.into_iter().map(|message| message.payload).collect()
}

#[tokio::test]
async fn the_notice_and_the_ledger_row_commit_together() {
    // THE ORDERING THIS API EXISTS FOR, and until now nothing measured it: every call passed
    // `event: None`, so the parameter added to make "recorded" and "announced" one fact was
    // exercised by no test at all.
    //
    // WHY IT MATTERS. A ledger row says "this customer has been told". If the row committed and
    // the announcement then failed, nothing would ever correct it -- `due()` filters on exactly
    // this row, no role may delete one, and no later sweep re-surfaces it. The customer is never
    // told and the ledger says they were, which is the outage #141 exists to prevent.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &org, "https://idp.example/i").await;
    let now = now_micros(&env);
    let alerts = db.control_store().scoped(scope).saml_certificate_alerts();
    let certificate = pin_expiring(&db, &env, scope, &connection, 30, 2 * DAY).await;

    let envelope = ironauth_store::event_catalog::envelope(
        "evt_cert_expiring",
        "saml_certificate.expiring",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        now / 1000,
        &serde_json::json!({
            "saml_certificate_id": certificate.to_string(),
            "saml_connection_id": connection.to_string(),
            "organization_id": org.to_string(),
            "lead_secs": 3 * DAY,
            "not_after_unix_ms": (now + 2 * DAY * 1_000_000) / 1000,
        }),
    )
    .expect("the expiring type is registered");

    alerts
        .record_sent(
            &env,
            &certificate,
            3 * DAY,
            now,
            Some(&ironauth_store::DomainEvent {
                id: "evt_cert_expiring",
                subject: &certificate.to_string(),
                envelope: &envelope,
            }),
        )
        .await
        .expect("record and announce");

    let announced = queued_events(&db, &env, scope).await;
    assert_eq!(announced.len(), 1, "the notice announced {announced:?}");
    assert_eq!(announced[0]["type"], "saml_certificate.expiring");
    assert_eq!(
        announced[0]["payload"]["lead_secs"],
        3 * DAY,
        "the notice does not carry the lead it was sent for: {announced:?}"
    );

    // AND A LOSER ANNOUNCES NOTHING. The conflict returns BEFORE the enqueue, so the second sweep
    // to reach this pair does not send a duplicate notice -- which is the half that makes the
    // primary key a delivery guarantee rather than just a uniqueness rule.
    let again = alerts
        .record_sent(
            &env,
            &certificate,
            3 * DAY,
            now + 1,
            Some(&ironauth_store::DomainEvent {
                id: "evt_cert_expiring_again",
                subject: &certificate.to_string(),
                envelope: &envelope,
            }),
        )
        .await;
    assert!(
        matches!(again, Err(StoreError::Conflict)),
        "a second send was not refused: {again:?}"
    );
    let after = queued_events(&db, &env, scope).await;
    assert!(
        after.is_empty(),
        "the losing sweep announced a duplicate notice: {after:?}"
    );
}

#[tokio::test]
async fn both_interval_bounds_are_driven_where_they_sit() {
    // NEITHER COMPARISON WAS DRIVEN AT ITS BOUNDARY. Every fixture sat a day or more either side,
    // so `<=` could become `<`, `>` could become `>=`, or the window could shrink by half a day,
    // and all of them stayed green. A lead is a promise about a moment; the moment is where it
    // has to be measured.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &org, "https://idp.example/j").await;
    let now = now_micros(&env);
    let alerts = db.control_store().scoped(scope).saml_certificate_alerts();
    let lead = 3 * DAY;

    // EXACTLY ON THE UPPER BOUND: expiring at `now + lead`. The clause is `<=`, so this is due --
    // a certificate exactly a lead away has just entered the window.
    let on_bound = pin_at(&db, &env, scope, &connection, 40, now + lead * 1_000_000).await;
    // ONE MICROSECOND PAST IT: not yet due, which is the other side of the same comparison.
    let past_bound = pin_at(
        &db,
        &env,
        scope,
        &connection,
        41,
        now + lead * 1_000_000 + 1,
    )
    .await;
    // EXACTLY AT EXPIRY: the lower clause is `>`, so a certificate expiring at this instant is
    // NOT due for a warning -- there is no time left to warn about.
    let at_expiry = pin_at(&db, &env, scope, &connection, 42, now).await;
    // ONE MICROSECOND BEFORE EXPIRY: still alive, so still due.
    let barely_alive = pin_at(&db, &env, scope, &connection, 43, now + 1).await;

    let due = alerts.due(now, &[lead], 100).await.expect("due");
    let ids: Vec<&str> = due
        .iter()
        .map(|entry| entry.certificate_id.as_str())
        .collect();

    assert!(
        ids.contains(&on_bound.to_string().as_str()),
        "a certificate exactly one lead from expiry is not due, so the upper bound is `<` not \
         `<=`: {due:?}"
    );
    assert!(
        !ids.contains(&past_bound.to_string().as_str()),
        "a certificate one microsecond beyond the lead is due, so the window is too wide: {due:?}"
    );
    assert!(
        !ids.contains(&at_expiry.to_string().as_str()),
        "a certificate expiring at this instant is queued for a WARNING: {due:?}"
    );
    assert!(
        ids.contains(&barely_alive.to_string().as_str()),
        "a certificate one microsecond from expiry is not due, so the lower bound is `>=` not \
         `>`: {due:?}"
    );
}

#[tokio::test]
async fn the_soonest_expiry_comes_first_and_a_repeated_lead_is_one_lead() {
    // TWO CLAIMS THE RUSTDOC MAKES AND NOTHING MEASURED. The ordering paragraph exists because a
    // sweep that is behind finds more work than it can send in one pass, and the certificates
    // closest to breaking are the ones whose notices matter most -- so a reversed sort is a real
    // regression, and it could be reversed with every test green. The DISTINCT was added in round
    // 1 with no test passing a repeated lead at all.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &org, "https://idp.example/k").await;
    let now = now_micros(&env);
    let alerts = db.control_store().scoped(scope).saml_certificate_alerts();

    // Pinned OUT of order, so a passing run cannot be insertion order.
    let later = pin_expiring(&db, &env, scope, &connection, 44, 20 * DAY).await;
    let sooner = pin_expiring(&db, &env, scope, &connection, 45, 2 * DAY).await;

    let due = alerts.due(now, &[30 * DAY], 100).await.expect("due");
    let ids: Vec<&str> = due
        .iter()
        .map(|entry| entry.certificate_id.as_str())
        .collect();
    assert_eq!(
        ids,
        vec![sooner.to_string().as_str(), later.to_string().as_str()],
        "the soonest expiry is not first, so a truncated sweep would drop the urgent one: {due:?}"
    );

    // AND THE LIMIT TAKES THE SOONEST, which is what makes the ordering worth having.
    let one = alerts.due(now, &[30 * DAY], 1).await.expect("due");
    assert_eq!(one.len(), 1);
    assert_eq!(
        one[0].certificate_id,
        sooner.to_string(),
        "a limited sweep took the later certificate: {one:?}"
    );

    // A REPEATED LEAD IS ONE LEAD. Without the DISTINCT this yields each pair twice, so a sweep
    // sends two identical notices and the second `record_sent` answers Conflict for one it had
    // just delivered.
    let repeated = alerts
        .due(now, &[30 * DAY, 30 * DAY], 100)
        .await
        .expect("due");
    assert_eq!(
        repeated.len(),
        2,
        "a lead named twice produced the pair twice: {repeated:?}"
    );
}

#[tokio::test]
async fn a_failure_after_the_notice_rolls_the_ledger_row_back() {
    // THE ATOMICITY CLAIM, MEASURED. Its sibling above observes a SUCCESSFUL call and a losing
    // one, and neither can tell one transaction from two: success leaves a row and a message
    // either way, and the conflict returns before the enqueue either way. Splitting `record_sent`
    // so the row commits alone and the notice goes in a SECOND transaction left all ten tests
    // green -- and that split IS the failure the doc warns about, a ledger saying a customer was
    // told when the notice never went out and nothing can correct it.
    //
    // So this forces an error after both writes are staged and requires BOTH to be gone. That is
    // the technique `write_audited` already carries for the same reason.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &org, "https://idp.example/l").await;
    let now = now_micros(&env);
    let alerts = db.control_store().scoped(scope).saml_certificate_alerts();
    let certificate = pin_expiring(&db, &env, scope, &connection, 50, 2 * DAY).await;

    let envelope = ironauth_store::event_catalog::envelope(
        "evt_cert_poisoned",
        "saml_certificate.expiring",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        now / 1000,
        &serde_json::json!({
            "saml_certificate_id": certificate.to_string(),
            "saml_connection_id": connection.to_string(),
            "organization_id": org.to_string(),
            "lead_secs": 3 * DAY,
            "not_after_unix_ms": (now + 2 * DAY * 1_000_000) / 1000,
        }),
    )
    .expect("registered");

    let outcome = alerts
        .record_sent_injecting_post_enqueue_failure(
            &env,
            &certificate,
            3 * DAY,
            now,
            Some(&ironauth_store::DomainEvent {
                id: "evt_cert_poisoned",
                subject: &certificate.to_string(),
                envelope: &envelope,
            }),
        )
        .await;
    assert!(
        matches!(outcome, Err(StoreError::Database(_))),
        "the poisoned write must fail: {outcome:?}"
    );

    // NEITHER WRITE SURVIVES. The notice is not in the outbox...
    let announced = queued_events(&db, &env, scope).await;
    assert!(
        announced.is_empty(),
        "a notice survived a rolled-back write: {announced:?}"
    );
    // ...and the pair is STILL DUE, which is the half that matters operationally: the next sweep
    // picks it up and the customer is told. A ledger row surviving here is the silent failure.
    let due = alerts.due(now, &[3 * DAY], 100).await.expect("due");
    assert_eq!(
        due.len(),
        1,
        "the ledger row survived a rolled-back notice, so this customer is never told: {due:?}"
    );

    // AND THE CONTROL: without the poison the same call succeeds, so the emptiness above is the
    // rollback and not a call that cannot work.
    alerts
        .record_sent(
            &env,
            &certificate,
            3 * DAY,
            now,
            Some(&ironauth_store::DomainEvent {
                id: "evt_cert_ok",
                subject: &certificate.to_string(),
                envelope: &envelope,
            }),
        )
        .await
        .expect("the unpoisoned write succeeds");
    assert_eq!(queued_events(&db, &env, scope).await.len(), 1);
}

#[tokio::test]
async fn a_certificate_unpinned_under_the_sweep_is_not_found_rather_than_a_fault() {
    // THE LIKELIEST RACE ON THIS PATH, and round 2 shipped the mapping for it with no test: the
    // SQLSTATE constant could be changed by one character, or the whole match arm deleted, and
    // everything stayed green.
    //
    // It is not exotic. A sweep reads `due()`, and before it records the notice an operator
    // replaces the certificate -- which is exactly what the warning asked them to do. Left as
    // `Database` that reads as a persistence fault and pages somebody; it means "that work item
    // is gone".
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &org, "https://idp.example/m").await;
    let now = now_micros(&env);
    let certificate = pin_expiring(&db, &env, scope, &connection, 51, 2 * DAY).await;

    // The sweep has its work item...
    let due = db
        .control_store()
        .scoped(scope)
        .saml_certificate_alerts()
        .due(now, &[3 * DAY], 100)
        .await
        .expect("due");
    assert_eq!(due.len(), 1, "the fixture is not due: {due:?}");

    // ...and the operator renews the certificate before the notice is recorded.
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .saml_connections()
        .unpin_certificate(&env, &certificate, None)
        .await
        .expect("unpin");

    let outcome = db
        .control_store()
        .scoped(scope)
        .saml_certificate_alerts()
        .record_sent(&env, &certificate, 3 * DAY, now, None)
        .await;
    assert!(
        matches!(outcome, Err(StoreError::NotFound)),
        "a certificate unpinned under the sweep is a persistence fault rather than a vanished \
         work item: {outcome:?}"
    );
}

#[tokio::test]
async fn the_work_item_names_the_certificates_own_organization() {
    // THE SWEEP WILL ROUTE ON THIS FIELD -- no sweep exists yet, and the struct's own doc says so
    // -- so getting it wrong would tell one customer about another
    // customer's identity provider -- and both organizations are in the same scope, so no
    // tenant fence catches it.
    //
    // TWO ORGANIZATIONS, EACH WITH A CONNECTION AND A DUE CERTIFICATE, so a build that returned
    // "an organization" rather than "this certificate's" has something to get wrong and both
    // rows are in the result set at once. An earlier field test kept a decoy that the lead
    // filtered out before the assertion ran, which measured nothing.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acme = seed_org(&db, &env, scope, "Acme").await;
    let globex = seed_org(&db, &env, scope, "Globex").await;
    let acme_connection = connect(&db, &env, scope, &acme, "https://idp.example/acme").await;
    let globex_connection = connect(&db, &env, scope, &globex, "https://idp.example/globex").await;
    let now = now_micros(&env);

    // Different expiries so the ORDER is known, and both inside the lead.
    let acme_cert = pin_expiring(&db, &env, scope, &acme_connection, 60, DAY).await;
    let globex_cert = pin_expiring(&db, &env, scope, &globex_connection, 61, 2 * DAY).await;

    let due = db
        .control_store()
        .scoped(scope)
        .saml_certificate_alerts()
        .due(now, &[3 * DAY], 100)
        .await
        .expect("due");
    assert_eq!(due.len(), 2, "both certificates are due: {due:?}");

    let pairs: Vec<(&str, &str)> = due
        .iter()
        .map(|entry| {
            (
                entry.certificate_id.as_str(),
                entry.organization_id.as_str(),
            )
        })
        .collect();
    assert_eq!(
        pairs,
        vec![
            (acme_cert.to_string().as_str(), acme.to_string().as_str()),
            (
                globex_cert.to_string().as_str(),
                globex.to_string().as_str()
            ),
        ],
        "a certificate is paired with the wrong organization, so its notice would go to the \
         wrong customer's contacts: {due:?}"
    );
}

#[tokio::test]
async fn a_certificate_of_a_removed_organization_is_not_due() {
    // A POLICY DECISION, NOT A DERIVATION, and the store doc on `due()` says the same. An
    // organization an operator has removed should not generate operational notices to its
    // contacts, because the operator has said they are done with it.
    //
    // TWO EARLIER REASONS HERE WERE MEASURABLY FALSE, which is why this one is labelled for what
    // it is. "Its contacts are gone": they are not. "It signs nobody in": it does -- removal
    // writes `organizations.deleted_at` and nothing else, and the SAML sign-in path never reads
    // that column. Both are exactly why the filter has to be explicit: nothing downstream would
    // stop the notice going out.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let doomed = seed_org(&db, &env, scope, "Doomed").await;
    let living = seed_org(&db, &env, scope, "Living").await;
    let doomed_connection = connect(&db, &env, scope, &doomed, "https://idp.example/gone").await;
    let living_connection = connect(&db, &env, scope, &living, "https://idp.example/here").await;
    let now = now_micros(&env);
    pin_expiring(&db, &env, scope, &doomed_connection, 70, 2 * DAY).await;
    let survivor = pin_expiring(&db, &env, scope, &living_connection, 71, 2 * DAY).await;

    // BOTH ARE DUE WHILE BOTH ORGANIZATIONS LIVE, so the filter below is what changes the answer
    // and not the fixture.
    let alerts = db.control_store().scoped(scope).saml_certificate_alerts();
    let due = alerts.due(now, &[3 * DAY], 100).await.expect("due");
    assert_eq!(due.len(), 2, "both certificates start out due: {due:?}");

    db.control_store()
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .organizations(scope)
        .delete(&env, &doomed)
        .await
        .expect("remove the organization");

    let due = alerts.due(now, &[3 * DAY], 100).await.expect("due");
    assert_eq!(
        due.len(),
        1,
        "a certificate of a removed organization is still queued for an operational notice its \
         operator has said they are done with: {due:?}"
    );
    assert_eq!(
        due[0].certificate_id,
        survivor.to_string(),
        "the wrong certificate survived the filter: {due:?}"
    );

    // AND DISABLING IS NOT DELETING. `organizations` carries two lifecycle facts and only
    // deletion suppresses the notice. Disabling is reversible and administrative -- the customer
    // exists, their contacts are there, the certificate is theirs -- so an organization disabled
    // across its lead windows must not come back with a dead certificate nobody warned them
    // about. Pinned here so the distinction is a decision somebody made rather than the accident
    // of having filtered one column.
    db.control_store()
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .organizations(scope)
        .set_state(
            &env,
            &living,
            ironauth_store::OrganizationState::Disabled,
            None,
        )
        .await
        .expect("disable the organization");
    let due = alerts.due(now, &[3 * DAY], 100).await.expect("due");
    assert_eq!(
        due.len(),
        1,
        "a disabled organization stopped being warned, so it can come back to a dead \
         certificate: {due:?}"
    );
}

#[tokio::test]
async fn another_scopes_certificate_is_not_due_here() {
    // THE LEDGER IS SCOPED LIKE EVERYTHING ELSE. A sweep running for one environment must not
    // find another's certificates, or it would notify one customer's contacts about another
    // customer's identity provider.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let mine = db.seed_scope(&env).await;
    let theirs = db.seed_scope(&env).await;
    let now = now_micros(&env);

    let their_org = seed_org(&db, &env, theirs, "Initech").await;
    let their_connection = connect(&db, &env, theirs, &their_org, "https://idp.example/e").await;
    pin_expiring(&db, &env, theirs, &their_connection, 8, 2 * DAY).await;

    let due = db
        .control_store()
        .scoped(mine)
        .saml_certificate_alerts()
        .due(now, LEADS, 100)
        .await
        .expect("due");
    assert!(
        due.is_empty(),
        "another environment's certificate is due in this one: {due:?}"
    );

    // AND THE WRITE SIDE IS FENCED TOO, which the read side above says nothing about. 0208's
    // foreign key names the certificate by id ALONE and referential integrity bypasses row-level
    // security, so without a guard in the repository this insert would SUCCEED: a ledger row in
    // one tenant's table against another tenant's certificate, invisible to `due()` here,
    // undeletable (no DELETE grant), and cascade-removed by a stranger. It would also tell a
    // caller apart a real foreign id from a fabricated one.
    let their_certificate = db
        .control_store()
        .scoped(theirs)
        .saml_certificate_alerts()
        .due(now, LEADS, 1)
        .await
        .expect("due")
        .first()
        .map(|entry| entry.certificate_id.clone())
        .expect("their certificate is due in their own scope");
    let parsed = ironauth_store::SamlCertificateId::parse_in_scope(&their_certificate, &theirs)
        .expect("their certificate id parses in their scope");
    let outcome = db
        .control_store()
        .scoped(mine)
        .saml_certificate_alerts()
        .record_sent(&env, &parsed, 3 * DAY, now, None)
        .await;
    assert!(
        matches!(outcome, Err(StoreError::NotFound)),
        "a ledger row was written against another scope's certificate: {outcome:?}"
    );

    // THE CONTROL: it IS due in its own scope, so the emptiness above is the fence and not an
    // empty table.
    let due = db
        .control_store()
        .scoped(theirs)
        .saml_certificate_alerts()
        .due(now, LEADS, 100)
        .await
        .expect("due");
    assert_eq!(
        due.len(),
        3,
        "the certificate is not due in its own scope: {due:?}"
    );
}
