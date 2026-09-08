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
    let now = now_micros(&env);
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
    // THE MILLISECOND FIELDS ARE CHECKED AS MILLISECONDS, not merely for presence. A value in
    // MICROSECONDS in a field named `_ms` puts a vendor's "renew before" date roughly two and a
    // half million years out, and the registry types it as a bare `integer` so nothing else
    // would notice. The bound is generous and still a thousand times tighter than the error.
    let expected_ms = (now + 2 * DAY * 1_000_000) / 1000;
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
            // AND THE CONNECTION, which is the thing an operator has to go and fix. Nothing read
            // it before, so it could have carried the certificate id instead.
            assert_eq!(
                event["payload"]["saml_connection_id"],
                connection.to_string(),
                "the notice names the wrong connection: {event}"
            );
            let not_after = event["payload"]["not_after_unix_ms"]
                .as_i64()
                .expect("an expiry");
            assert!(
                (not_after - expected_ms).abs() < 1000,
                "the expiry is not the certificate's, in milliseconds: {not_after} against \
                 {expected_ms}"
            );
            // AGAINST THE KNOWN VALUE, not against a ceiling. An earlier version asserted only
            // `occurred < a_century_ms`, which a SECONDS value passes comfortably -- 1.8e9 is
            // far under 3.2e12 -- so the assertion could not support the label it carried. It
            // caught microseconds by luck of magnitude and nothing else. A window around the
            // expected millisecond value rejects both directions.
            let occurred = event["occurred_at_unix_ms"].as_i64().expect("a timestamp");
            assert!(
                (occurred - now / 1000).abs() < 60_000,
                "the envelope's occurred_at is not the pass's clock in milliseconds: {occurred} \
                 against {}",
                now / 1000
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
    // AND THE LOSER REPORTED WHAT IT LOST. This is the assertion that makes `already_taken`
    // mean something: whichever pass ran second saw the other's rows and counted them rather
    // than raising. An earlier version asserted `announced + already_taken >= 3`, which is
    // implied by the line above -- `announced` already sums to 3 -- so it held whatever
    // `already_taken` was, including zero. That is the second vacuous guard I wrote here.
    //
    // The passes may genuinely not overlap, in which case the second finds nothing due and
    // reports zero of everything; what must never happen is a pass that RAISED, and both
    // `expect`s above already forbid that.
    // WHAT THIS TEST CAN AND CANNOT GUARANTEE, stated because two earlier versions pretended
    // otherwise. It guarantees the invariant above: three notices between the two passes, no
    // more and no fewer, and neither pass raising. It does NOT guarantee that the passes
    // OVERLAP -- they may serialise, in which case the second finds nothing due and reports
    // zero of everything, and `already_taken` is never exercised.
    //
    // Two earlier guards here claimed to cover that and did not. One was arithmetic that
    // reduced to a tautology; the other asserted `announced + already_taken >= 3`, which the
    // line above already forces since `announced` sums to exactly 3. Asserting
    // `already_taken > 0` instead would be worse: it would be FLAKY, red whenever the runtime
    // happened to serialise the two futures.
    //
    // So the count is bounded and nothing more is claimed of it.
    let contested = left.already_taken + right.already_taken;
    assert!(
        contested <= 3,
        "more pairs were reported taken than there are thresholds: {left:?} {right:?}"
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
    // WHERE IT DROPS OUT WHEN THE UNPIN IS ALREADY DONE: the certificate leaves `due()`, so a
    // pass never attempts it and `vanished` stays zero. The counter is for the NARROWER
    // interleaving where the unpin lands between a pass reading and writing, which
    // `a_renewal_landing_mid_pass_is_counted_not_raised` below constructs.
    //
    // An earlier version of this test asserted three `already_taken` from rows staged BEFORE the
    // pass, which `due()` simply excludes -- a state the code cannot produce.
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

#[tokio::test]
async fn a_renewal_landing_mid_pass_is_counted_not_raised() {
    // THE `vanished` ARM, ACTUALLY EXERCISED. Its sibling above shows an unpin that has already
    // happened simply removes the work item; this drives the interleaving the counter exists
    // for -- the operator renewing WHILE a pass is running, which is the likeliest timing of all
    // given the notice is what prompted them.
    //
    // AND IT WAS UNREACHED BEFORE. A review measured it: replacing the arm with
    // `report.announced += 1`, or with a `panic!`, left every test in this file green -- so a
    // pass that lost every work item to renewals would have reported them all as announced. The
    // comment that explained the gap away claimed the interleaving was not constructible from
    // one task. It is, with the same `tokio::join!` its neighbour uses.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &org, "https://idp.example/midpass").await;

    // SEVERAL CERTIFICATES, so the pass has enough work to still be running when the unpin
    // lands. One would be a race the sweep usually wins.
    let mut pinned = Vec::new();
    for seed in 90..100u8 {
        pinned.push(pin_expiring(&db, &env, scope, &connection, seed, 2 * DAY).await);
    }
    drain(&db, &env, scope).await;
    let victim = *pinned.last().expect("ten certificates");

    let (report, unpinned) = tokio::join!(
        ironauth_admin::certificate_expiry::run_once(db.control_store(), &env, scope, LEADS, 100),
        async {
            tokio::time::sleep(std::time::Duration::from_millis(3)).await;
            db.control_store()
                .scoped(scope)
                .acting(db.test_actor(&env), CorrelationId::generate(&env))
                .saml_connections()
                .unpin_certificate(&env, &victim, None)
                .await
        },
    );
    unpinned.expect("the operator's renewal succeeds");
    let report = report.expect("a renewal under a pass is not a fault");

    // THE VICTIM'S PAIRS LANDED IN THE `vanished` BUCKET, which is the assertion that gives the
    // counter meaning. An earlier version asserted only `announced + vanished == 30`, and that
    // sum is INSENSITIVE to which bucket a pair falls in -- counting a vanished pair as
    // announced keeps the total at thirty, so the mutation this test exists to catch survived
    // it. The third vacuous assertion I have written in this file, and the one that would have
    // let a pass report every lost work item as delivered.
    //
    // THIS DEPENDS ON THE PASS STILL RUNNING when the unpin lands, which is why there are ten
    // certificates rather than one: the sweep has thirty records to write and the renewal
    // arrives after three milliseconds.
    assert!(
        report.vanished > 0,
        "the renewal landed without the pass noticing, so the interleaving this test exists for \
         did not happen: {report:?}"
    );
    assert_eq!(
        report.announced + report.vanished,
        30,
        "pairs went missing under a mid-pass renewal: {report:?}"
    );
    assert_eq!(
        report.already_taken, 0,
        "no other pass was running, so nothing can have been taken: {report:?}"
    );
}

#[tokio::test]
async fn a_clock_before_the_epoch_is_a_clock_fault_and_says_so() {
    // THE `Clock` ARM, EXERCISED. Round 2 gave the sweep its own error type precisely so a
    // failure would say what happened rather than "envelope decryption failed" -- and then left
    // one of its four arms reached by no test, which is how the previous round's fix keeps
    // becoming the next round's defect.
    //
    // NOT A HYPOTHETICAL. `Env::deterministic` takes any `SystemTime`, and a deployment whose
    // clock is wrong before it is set is the ordinary cause; the sweep reads that clock to decide
    // what is due, so it has to refuse rather than compute a window from a negative instant.
    let db = TestDatabase::start().await;
    let seeded = Env::system();
    let scope = db.seed_scope(&seeded).await;
    let org = seed_org(&db, &seeded, scope, "Globex").await;
    let connection = connect(&db, &seeded, scope, &org, "https://idp.example/clock").await;
    pin_expiring(&db, &seeded, scope, &connection, 110, 2 * DAY).await;

    // A CLOCK AN HOUR BEFORE THE UNIX EPOCH.
    let (broken, _handle) = Env::deterministic(
        std::time::SystemTime::UNIX_EPOCH - std::time::Duration::from_secs(3600),
        7,
    );
    let outcome = ironauth_admin::certificate_expiry::run_once(
        db.control_store(),
        &broken,
        scope,
        LEADS,
        100,
    )
    .await;

    let message = match outcome {
        Err(error) => error.to_string(),
        Ok(report) => panic!("a pre-epoch clock produced a pass rather than a fault: {report:?}"),
    };
    // AND THE MESSAGE NAMES THE CLOCK. Whoever is paged by this is being sent somewhere; before
    // round 2 they were told the envelope failed to decrypt, which would send them to the
    // crypto layer for a wrong system clock.
    assert!(
        message.contains("clock"),
        "the failure does not name the clock, so it sends the reader elsewhere: {message}"
    );
}
