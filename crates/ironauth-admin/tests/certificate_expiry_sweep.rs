// SPDX-License-Identifier: MIT OR Apache-2.0

//! One pass of the certificate expiry sweep (issue #141), over a real database.
//!
//! # What a pass owes
//!
//! Exactly one `saml_certificate.expiring` per (certificate, lead) that has crossed its
//! threshold, ever -- and the two ways a pass can lose a race are outcomes it reports rather than
//! faults it raises. Both matter operationally: a sweep is a job an operator runs twice, and an
//! expiry warning is precisely what prompts the certificate replacement that makes the work item
//! vanish underneath it.

#![cfg(feature = "testing")]

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, NewSamlCertificate, NewSamlConnection, OrganizationId, SamlCertificateId,
    SamlConnectionId, SamlKeyKind, Scope,
};
use serde_json::json;

const DAY: i64 = 24 * 60 * 60;
const LEADS: &[i64] = &[30 * DAY, 14 * DAY, 3 * DAY];

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

/// Claim and complete everything in the outbox, LOOPING to empty.
///
/// A SINGLE CLAIM IS NOT A DRAIN HERE, and this test found that the hard way: the outbox
/// serializes per ordering key, and all three notices about one certificate share its id as their
/// subject -- so the second is not claimable until the first is COMPLETED. One pass returned one
/// event and the test read that as "the sweep announced once".
async fn drain(db: &TestDatabase, env: &Env, scope: Scope) -> Vec<serde_json::Value> {
    let mut seen = Vec::new();
    loop {
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
        if claimed.is_empty() {
            return seen;
        }
        for message in claimed {
            seen.push(message.payload.clone());
            db.store()
                .scoped(scope)
                .outbox()
                .complete(env, &message)
                .await
                .expect("complete");
        }
    }
}

#[tokio::test]
async fn a_pass_announces_every_crossed_lead_once_and_a_second_pass_announces_nothing() {
    // THE WHOLE POINT, IN ONE TEST. A certificate two days out has crossed all three thresholds,
    // so the first pass owes three notices; the second owes none, because the ledger records what
    // the first sent. A sweep that re-announced on every pass would be filtered into a folder
    // nobody reads, which is the same outcome as never warning at all.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &org, "https://idp.example/sweep").await;
    let certificate = pin_expiring(&db, &env, scope, &connection, 80, 2 * DAY).await;
    drain(&db, &env, scope).await;

    let report =
        ironauth_admin::certificate_expiry::run_once(db.control_store(), &env, scope, LEADS, 100)
            .await
            .expect("first pass");
    assert_eq!(
        report.announced, 3,
        "the first pass owed three notices: {report:?}"
    );
    assert_eq!(report.already_taken, 0);
    assert_eq!(report.vanished, 0);

    let announced = drain(&db, &env, scope).await;
    assert_eq!(announced.len(), 3, "the pass announced {announced:?}");
    let mut leads: Vec<i64> = announced
        .iter()
        .map(|event| {
            assert_eq!(event["type"], "saml_certificate.expiring");
            // THE ORGANIZATION TRAVELS, which is what lets a per-organization consumer route it
            // without reading the connection back to learn whose certificate this is.
            assert_eq!(event["payload"]["organization_id"], org.to_string());
            assert_eq!(
                event["payload"]["saml_certificate_id"],
                certificate.to_string()
            );
            event["payload"]["lead_secs"].as_i64().expect("a lead")
        })
        .collect();
    leads.sort_unstable();
    assert_eq!(
        leads,
        vec![3 * DAY, 14 * DAY, 30 * DAY],
        "the three notices are not one per crossed threshold"
    );

    // AND A SECOND PASS OWES NOTHING.
    let report =
        ironauth_admin::certificate_expiry::run_once(db.control_store(), &env, scope, LEADS, 100)
            .await
            .expect("second pass");
    assert_eq!(
        report,
        ironauth_admin::certificate_expiry::SweepReport::default(),
        "a second pass found work: {report:?}"
    );
    assert!(
        drain(&db, &env, scope).await.is_empty(),
        "a second pass announced a notice already sent"
    );
}

#[tokio::test]
async fn two_passes_racing_over_one_certificate_announce_it_once_between_them() {
    // A SWEEP IS A JOB AN OPERATOR RUNS TWICE, so this drives the interleaving rather than
    // simulating it. Staging the ledger rows BEFORE a pass does not reach this code at all --
    // `due()` already excludes recorded pairs, so the pass finds nothing and the loop never runs.
    // The `already_taken` branch is reachable only when a second pass records BETWEEN this one
    // reading and writing, which is what two concurrent passes produce.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &org, "https://idp.example/races").await;
    pin_expiring(&db, &env, scope, &connection, 81, 2 * DAY).await;
    drain(&db, &env, scope).await;

    let (left, right) = tokio::join!(
        ironauth_admin::certificate_expiry::run_once(db.control_store(), &env, scope, LEADS, 100),
        ironauth_admin::certificate_expiry::run_once(db.control_store(), &env, scope, LEADS, 100),
    );
    let left = left.expect("a losing pass reports rather than raises");
    let right = right.expect("a losing pass reports rather than raises");

    // EXACTLY THREE NOTICES BETWEEN THEM, however the two passes divided the work. That is the
    // guarantee the ledger's primary key gives, and it holds whichever way the interleaving fell.
    assert_eq!(
        left.announced + right.announced,
        3,
        "two passes announced {} notices between them for three thresholds: {left:?} {right:?}",
        left.announced + right.announced
    );
    // AND NOTHING WAS LOST OR RAISED. Every pair either announced or was reported as taken, and
    // nothing vanished -- the certificate is still pinned throughout.
    assert_eq!(
        left.vanished + right.vanished,
        0,
        "a pass reported a vanished certificate that was never unpinned: {left:?} {right:?}"
    );
    let accounted = left.announced + left.already_taken + right.announced + right.already_taken;
    assert!(
        accounted >= 3,
        "the two passes accounted for {accounted} of three thresholds, so a pair was silently \
         dropped: {left:?} {right:?}"
    );

    let announced = drain(&db, &env, scope).await;
    assert_eq!(
        announced.len(),
        3,
        "the outbox holds {} notices for three thresholds: {announced:?}",
        announced.len()
    );
}

#[tokio::test]
async fn an_unpinned_certificate_leaves_the_work_set_rather_than_failing_a_pass() {
    // AN EXPIRY WARNING IS WHAT PROMPTS THE RENEWAL, so losing the work item to the operator
    // acting on it is a SUCCESS of the feature and must not read as a fault.
    //
    // WHERE IT ACTUALLY DROPS OUT, measured rather than assumed: the certificate leaves `due()`
    // the moment it is unpinned, so a pass never attempts it and `vanished` stays zero. That
    // counter exists for the narrower interleaving where the unpin lands BETWEEN a pass reading
    // and writing, which is not constructible from one task -- and an earlier version of this
    // test asserted three `already_taken` from rows staged BEFORE the pass, which `due()` simply
    // excludes, so it was asserting a state the code cannot produce.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &org, "https://idp.example/renewed").await;
    let renewed = pin_expiring(&db, &env, scope, &connection, 82, 2 * DAY).await;
    let other = pin_expiring(&db, &env, scope, &connection, 83, 2 * DAY).await;
    drain(&db, &env, scope).await;

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .saml_connections()
        .unpin_certificate(&env, &renewed, None)
        .await
        .expect("the operator replaces the certificate the warning is about");

    let report =
        ironauth_admin::certificate_expiry::run_once(db.control_store(), &env, scope, LEADS, 100)
            .await
            .expect("the pass does not fail on a certificate that was renewed under it");
    assert_eq!(
        report.announced, 3,
        "the surviving certificate's three thresholds were not announced: {report:?}"
    );
    assert_eq!(
        report.vanished, 0,
        "an unpinned certificate was attempted rather than dropped from the due set: {report:?}"
    );

    // AND EVERY NOTICE IS ABOUT THE CERTIFICATE THAT STILL EXISTS.
    let announced = drain(&db, &env, scope).await;
    assert_eq!(announced.len(), 3, "the pass announced {announced:?}");
    for event in &announced {
        assert_eq!(
            event["payload"]["saml_certificate_id"],
            other.to_string(),
            "a notice went out about the certificate the operator had already replaced: {event}"
        );
    }
}
