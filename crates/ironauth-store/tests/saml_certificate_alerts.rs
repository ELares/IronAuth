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
    // THREE OF FOUR FIELDS WERE NEVER READ. The tests matched on `certificate_id` and
    // `lead_secs` and never looked at `connection_id` or `not_after_unix_micros`, so both could
    // have been the wrong row's and nothing would have said. They are not decoration: the sweep
    // finds the organization to notify THROUGH `connection_id`, and puts the expiry date in the
    // notice it sends.
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
        "the entry names the wrong connection, so the sweep would notify the wrong organization"
    );
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
