// SPDX-License-Identifier: MIT OR Apache-2.0

//! Inbound SAML connections: which identity provider an organization signs in through, and on
//! what terms (issue #139), over a real database (`DATABASE_URL`).
//!
//! # What this table decides
//!
//! Every other connection in this system decides where data GOES. This one decides who may
//! assert an identity, which is the only kind of connection whose misconfiguration lets somebody
//! else sign in as your users. So the questions here are narrower and sharper than for an
//! outbound one: can a key pinned on one connection verify for another, can a response name the
//! organization it wants to be validated against, and does an operator's switch actually stop
//! trust.
//!
//! # The certificate is not the trust anchor
//!
//! `ironauth-saml` verifies against RAW key material and deliberately never parses X.509, so the
//! certificate is parsed once at pinning time and both halves are stored. Nothing on the
//! assertion path reads `certificate_der`, and the schema is shaped so a row that could not be
//! handed to the verifier -- an RSA key with no exponent, a P-256 point of the wrong length --
//! cannot be written at all.

#![cfg(feature = "testing")]

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, NewSamlCertificate, NewSamlConnection, OrganizationId, SamlCertificateId,
    SamlConnectionId, SamlKeyKind, Scope, StoreError,
};
use serde_json::json;

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

/// Pin a P-256 key, returning the handle.
async fn pin(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    connection: &SamlConnectionId,
    seed: u8,
) -> Result<SamlCertificateId, StoreError> {
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
                not_before_unix_micros: now - 1_000_000,
                not_after_unix_micros: now + 86_400_000_000,
            },
            None,
            None,
        )
        .await
        .map(|()| id)
}

#[tokio::test]
async fn a_connection_round_trips_and_holds_no_key_of_its_own() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &org, "https://idp.example/entity").await;

    let store = db.store().scoped(scope);
    let stored = store
        .saml_connections()
        .find_in_org(&org, &connection)
        .await
        .expect("read")
        .expect("the connection exists");
    assert_eq!(stored.idp_entity_id, "https://idp.example/entity");
    assert_eq!(stored.organization_id, org);
    assert!(!stored.allow_unsolicited, "unsolicited is off by default");
    assert!(stored.active);

    // A CONNECTION TRUSTS NOTHING UNTIL A KEY IS PINNED. Creating one is naming an identity
    // provider; it is not yet believing anything it says, and a connection that verified against
    // an empty anchor set would be one that accepted whatever arrived.
    let pinned = store
        .saml_connections()
        .certificates(&connection)
        .await
        .expect("read the pins");
    assert!(
        pinned.is_empty(),
        "a new connection already trusts a key: {pinned:?}"
    );
}

#[tokio::test]
async fn the_columns_the_verifier_and_the_conditions_read_round_trip_exactly() {
    // WHY THIS IS SEPARATE. The round-trip above uses the fixture, which supplies exactly the
    // column DEFAULT for every defaulted field -- so a read that dropped a column and returned
    // the default instead would have passed it. Every value here differs from its default, and
    // `public_key` is asserted BYTE FOR BYTE because it is the only column on the assertion path:
    // a truncation or a re-encoding there is a key that verifies nothing, reported as a forgery.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let id = SamlConnectionId::generate(&env, &scope);
    let mapping = json!({ "email": "urn:oid:0.9.2342.19200300.100.1.3" });
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .saml_connections()
        .create(
            &env,
            NewSamlConnection {
                id: &id,
                organization_id: &org,
                display_name: "Entra",
                idp_entity_id: "https://sts.windows.net/tenant/",
                idp_sso_url: "https://login.microsoftonline.com/tenant/saml2",
                sp_entity_id: "https://ironauth.example/saml/globex",
                acs_url: "https://ironauth.example/saml/acs/globex",
                // ALL FIVE DIFFER FROM THE DEFAULT.
                allow_unsolicited: true,
                clock_skew_secs: 5,
                max_assertion_age_secs: 120,
                nameid_format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
                attribute_mapping: &mapping,
                require_encrypted_assertion: true,
            },
            None,
            None,
        )
        .await
        .expect("create");

    let store = db.store().scoped(scope);
    let stored = store
        .saml_connections()
        .find_in_org(&org, &id)
        .await
        .expect("read")
        .expect("exists");
    assert!(stored.allow_unsolicited);
    assert_eq!(stored.clock_skew_secs, 5);
    assert_eq!(stored.max_assertion_age_secs, 120);
    assert_eq!(
        stored.nameid_format,
        "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
    );
    assert_eq!(stored.attribute_mapping, mapping);
    assert!(stored.require_encrypted_assertion);
    assert_eq!(stored.sp_entity_id, "https://ironauth.example/saml/globex");
    assert_eq!(stored.acs_url, "https://ironauth.example/saml/acs/globex");

    // AND THE KEY MATERIAL, byte for byte.
    let key = p256_point(7);
    let der = vec![0x30, 0x82, 0x07, 0xAB, 0xCD];
    let print = fingerprint(7);
    let cert_id = SamlCertificateId::generate(&env, &scope);
    let now = now_micros(&env);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .saml_connections()
        .pin_certificate(
            &env,
            NewSamlCertificate {
                id: &cert_id,
                connection_id: &id,
                key_kind: SamlKeyKind::Rsa,
                public_key: &vec![0xA5; 256],
                rsa_exponent: Some(&[0x01, 0x00, 0x01]),
                certificate_der: &der,
                fingerprint_sha256: &print,
                not_before_unix_micros: now - 1_000_000,
                not_after_unix_micros: now + 86_400_000_000,
            },
            None,
            None,
        )
        .await
        .expect("pin");
    let pins = store
        .saml_connections()
        .certificates(&id)
        .await
        .expect("read the pins");
    let pin = pins.first().expect("one pin");
    assert_eq!(pin.key_kind, SamlKeyKind::Rsa);
    assert_eq!(
        pin.public_key,
        vec![0xA5; 256],
        "the key the verifier is handed did not survive the round trip"
    );
    assert_eq!(
        pin.rsa_exponent.as_deref(),
        Some(&[0x01_u8, 0x00, 0x01][..]),
        "the RSA exponent did not survive; ring needs both halves"
    );
    assert_eq!(pin.certificate_der, der);
    assert_eq!(pin.fingerprint_sha256, print);
    assert_eq!(pin.not_before_unix_micros, now - 1_000_000);
    assert_eq!(pin.not_after_unix_micros, now + 86_400_000_000);
    let _ = key;
}

#[tokio::test]
async fn one_connections_pins_are_not_another_connections() {
    // The filter on `connection_id` in `certificates()`, which nothing measured: a read that
    // dropped it would hand one identity provider's key to a response from another, so a customer
    // whose IdP is compromised could assert identities on every connection in the environment.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let first = connect(&db, &env, scope, &org, "https://idp-a.example/entity").await;
    let second = connect(&db, &env, scope, &org, "https://idp-b.example/entity").await;
    pin(&db, &env, scope, &first, 1)
        .await
        .expect("pin the first");
    pin(&db, &env, scope, &second, 2)
        .await
        .expect("pin the second");

    let store = db.store().scoped(scope);
    let firsts = store
        .saml_connections()
        .certificates(&first)
        .await
        .expect("read");
    assert_eq!(
        firsts.len(),
        1,
        "one connection saw another's pins: {firsts:?}"
    );
    assert_eq!(firsts[0].public_key, p256_point(1));
    let seconds = store
        .saml_connections()
        .certificates(&second)
        .await
        .expect("read");
    assert_eq!(seconds.len(), 1);
    assert_eq!(seconds[0].public_key, p256_point(2));
}

#[tokio::test]
async fn the_assertion_consumer_resolves_by_connection_and_an_operator_switch_stops_it() {
    // WHY BY CONNECTION AND NOT BY ISSUER. Each connection publishes its own assertion consumer
    // URL, so the id is in the path a response arrives at, and the `Issuer` is CHECKED against
    // the resolved connection rather than used to find one.
    //
    // The first version looked connections up by issuer, and the configuration that breaks that
    // is ordinary: a customer with two organizations here signs both into their ONE identity
    // provider tenant, so both connections carry the same `idp_entity_id` and the lookup has two
    // rows and no basis for choosing. It returned whichever Postgres emitted first, so the
    // organization it reported was not determined by the response. The test below is the one that
    // could not have existed under that design.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let globex = seed_org(&db, &env, scope, "Globex").await;
    let initech = seed_org(&db, &env, scope, "Initech").await;
    // ONE IDENTITY PROVIDER, TWO ORGANIZATIONS. This must be a supported configuration, not a
    // conflict: it is a customer with two workspaces and one Okta.
    let one = connect(&db, &env, scope, &globex, "https://idp.example/entity").await;
    let two = connect(&db, &env, scope, &initech, "https://idp.example/entity").await;
    assert_ne!(one, two);
    // A PIN, so the assertion at the end that switching off keeps them is not satisfied by there
    // being none.
    pin(&db, &env, scope, &one, 3).await.expect("pin a key");
    let store = db.store().scoped(scope);

    let first = store
        .saml_connections()
        .find_active(&one)
        .await
        .expect("read")
        .expect("the connection resolves");
    assert_eq!(
        first.organization_id, globex,
        "the connection resolved to the wrong organization, which an issuer lookup could not \
         have got right at all"
    );
    let second = store
        .saml_connections()
        .find_active(&two)
        .await
        .expect("read")
        .expect("the connection resolves");
    assert_eq!(second.organization_id, initech);

    // AN OPERATOR'S SWITCH STOPS IT RESOLVING AT ALL.
    //
    // The lookup filters on `active`, and the first version of this slice had no way to set that
    // column: a filter nothing can make false is a defence in the shape of a comment. Removing
    // the filter left every test green, which is how it was found.
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .saml_connections()
        .set_active(&env, &one, false, None)
        .await
        .expect("switch the connection off");
    assert!(
        store
            .saml_connections()
            .find_active(&one)
            .await
            .expect("read")
            .is_none(),
        "a switched-off identity provider still resolves, so turning it off means only that the \
         management surface says so"
    );
    // AND THE OTHER ORGANIZATION'S IS UNTOUCHED, which is what proves the switch is per
    // connection and not per issuer.
    assert!(
        store
            .saml_connections()
            .find_active(&two)
            .await
            .expect("read")
            .is_some(),
        "switching one connection off disabled another organization's"
    );
    // THE ROW IS STILL THERE, with its pins, which is the difference from a deletion: switching
    // back on must not require re-pinning every key.
    let still_there = store
        .saml_connections()
        .find_in_org(&globex, &one)
        .await
        .expect("read")
        .expect("the connection was not deleted");
    assert!(!still_there.active);

    // AND THE TRAIL SAYS WHICH HAPPENED. The first version wrote the DELETION action for a
    // switch, beside a comment explaining why that would be wrong: an operator reading the log
    // could not tell a connection that was switched off from one that was removed, and only the
    // second lost its trust anchors. Nothing measured it, so the contradiction survived review.
    let action: String = sqlx::query_scalar(
        "SELECT action FROM audit_log WHERE target_id = $1 ORDER BY occurred_at DESC LIMIT 1",
    )
    .bind(one.to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("the switch wrote an audit row");
    assert_eq!(
        action, "saml_connection.disabled",
        "switching a connection off is byte-identical in the trail to deleting it"
    );

    // AND SWITCHING BACK ON IS A DIFFERENT ACTION. One action for both directions would make
    // "somebody turned this identity provider back on" indistinguishable from "somebody turned it
    // off" in the trail, which is the question an incident review asks first.
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .saml_connections()
        .set_active(&env, &one, true, None)
        .await
        .expect("switch the connection back on");
    let action: String = sqlx::query_scalar(
        "SELECT action FROM audit_log WHERE target_id = $1 ORDER BY occurred_at DESC, action \
         LIMIT 1",
    )
    .bind(one.to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("the switch wrote an audit row");
    assert_eq!(action, "saml_connection.enabled");

    // AND THE PINS SURVIVED IT, which is the whole reason the switch is not a deletion and was
    // asserted only in a comment before.
    let pins = store
        .saml_connections()
        .certificates(&one)
        .await
        .expect("read the pins");
    assert_eq!(
        pins.len(),
        1,
        "switching a connection off and on lost its trust anchors, so recovering from an incident \
         means re-pinning every key: {pins:?}"
    );
}

#[tokio::test]
async fn a_connection_in_another_organization_is_not_found() {
    // The IDOR shape this whole model exists for: a handle is not an authorization, and naming
    // the wrong organization beside a real connection must be indistinguishable from naming one
    // that does not exist.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let ours = seed_org(&db, &env, scope, "Globex").await;
    let theirs = seed_org(&db, &env, scope, "Initech").await;
    let connection = connect(&db, &env, scope, &ours, "https://idp.example/entity").await;

    let store = db.store().scoped(scope);
    assert!(
        store
            .saml_connections()
            .find_in_org(&theirs, &connection)
            .await
            .expect("read")
            .is_none(),
        "another organization's handle resolved"
    );
    // AND THE LISTING AGREES, which is the half a `find` alone would not cover: a listing that
    // filtered on the id and not the organization would leak the row into the wrong page.
    let listed = store
        .saml_connections()
        .list_for_org(&theirs, 50, None)
        .await
        .expect("list");
    assert!(
        listed.is_empty(),
        "the listing leaked a connection: {listed:?}"
    );
}

#[tokio::test]
async fn a_key_cannot_be_pinned_to_another_scopes_connection() {
    // REFERENTIAL INTEGRITY BYPASSES ROW-LEVEL SECURITY, so the foreign key resolves a connection
    // in any scope. What refuses one here is the `WHERE EXISTS` inside the insert, which runs
    // under the policy. Without it a control-plane caller pins a trust anchor onto somebody
    // else's connection, which is the strongest privilege this table has to give away.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let ours = db.seed_scope(&env).await;
    let theirs = db.seed_scope(&env).await;
    let their_org = seed_org(&db, &env, theirs, "Initech").await;
    let their_connection = connect(&db, &env, theirs, &their_org, "https://idp.example/e").await;

    // A handle from another scope: `pin_certificate` refuses it on the id check.
    let refused = pin(&db, &env, ours, &their_connection, 1).await;
    assert!(
        matches!(refused, Err(StoreError::NotFound)),
        "a key was pinned across scopes: {refused:?}"
    );

    // AND THE PIN DID NOT LAND, which is the assertion that matters: a verdict alone would pass
    // against a write that errored after inserting.
    let store = db.store().scoped(theirs);
    let pinned = store
        .saml_connections()
        .certificates(&their_connection)
        .await
        .expect("read the pins");
    assert!(pinned.is_empty(), "the refused pin was written: {pinned:?}");
}

#[tokio::test]
async fn a_key_cannot_be_pinned_to_a_connection_that_does_not_exist() {
    // THE `WHERE EXISTS` INSIDE THE INSERT, which the id-scope check shadows for a FOREIGN
    // handle and is the only thing covering a well-formed handle in THIS scope that names no row.
    //
    // Without it the insert reaches the foreign key and fails with a raw constraint violation
    // rather than a not-found, so a caller pinning to a connection somebody deleted a moment ago
    // gets a 500 where they should get a 404. Removing the clause left every test green, because
    // the only pinning test that expected a refusal handed it a cross-scope handle.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let absent = SamlConnectionId::generate(&env, &scope);

    let refused = pin(&db, &env, scope, &absent, 1).await;
    assert!(
        matches!(refused, Err(StoreError::NotFound)),
        "pinning to a connection that does not exist was not a not-found: {refused:?}"
    );
}

#[tokio::test]
async fn several_keys_are_pinned_at_once_so_a_rotation_is_not_an_outage() {
    // WHY PLURAL. An identity provider rotates its signing certificate on its own schedule. A
    // connection that could pin one key would break at every rotation, bounded by how fast
    // somebody noticed, so an operator pins the new certificate BEFORE the switch and removes the
    // old one after. The overlap is the rows that exist at the same time.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &org, "https://idp.example/entity").await;

    let old = pin(&db, &env, scope, &connection, 1)
        .await
        .expect("pin the current key");
    let new = pin(&db, &env, scope, &connection, 2)
        .await
        .expect("pin the incoming key");

    let store = db.store().scoped(scope);
    let pinned = store
        .saml_connections()
        .certificates(&connection)
        .await
        .expect("read the pins");
    assert_eq!(pinned.len(), 2, "both keys must verify during a rollover");
    assert!(pinned.iter().any(|c| c.id == old));
    assert!(pinned.iter().any(|c| c.id == new));

    // AND THE SAME KEY CANNOT BE PINNED TWICE, because "remove the old certificate" would then be
    // ambiguous, during exactly the operation an operator performs under time pressure.
    let duplicate = pin(&db, &env, scope, &connection, 1).await;
    assert!(
        matches!(duplicate, Err(StoreError::Conflict)),
        "one key was pinned twice on one connection: {duplicate:?}"
    );

    // UNPINNING THE OLD ONE LEAVES THE NEW ONE, which is the second half of the rollover.
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .saml_connections()
        .unpin_certificate(&env, &old, None)
        .await
        .expect("unpin the retired key");
    let after = store
        .saml_connections()
        .certificates(&connection)
        .await
        .expect("read the pins");
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].id, new);
}

#[tokio::test]
async fn deleting_a_connection_takes_its_trust_anchors_with_it() {
    // Leaving pins behind would leave trust anchors in the table for a connection an operator
    // believes they deleted, and a later connection reusing the identity provider would inherit
    // keys nobody re-approved.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &org, "https://idp.example/entity").await;
    pin(&db, &env, scope, &connection, 1).await.expect("pin");

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .saml_connections()
        .delete(&env, &connection, None)
        .await
        .expect("delete the connection");

    let store = db.store().scoped(scope);
    assert!(
        store
            .saml_connections()
            .find_in_org(&org, &connection)
            .await
            .expect("read")
            .is_none()
    );
    // READ THROUGH THE PARENT, which answers empty for a deleted parent whatever the child holds,
    // so the row count is read directly instead.
    let orphans: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM saml_connection_certificates WHERE connection_id = $1",
    )
    .bind(connection.to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("count the orphans");
    assert_eq!(orphans, 0, "trust anchors outlived their connection");
}

#[tokio::test]
async fn one_organization_cannot_pin_two_connections_to_one_identity_provider() {
    // NOT BECAUSE THE ACS WOULD BE AMBIGUOUS -- it resolves a response by the URL it arrived at,
    // so two connections naming one identity provider are told apart the same way any two are.
    // The reason is an operator's: two connections in one organization for one identity provider
    // are two sets of trust anchors for one relationship, and every question about it -- which
    // keys are current, which to revoke, why a sign-in failed -- then has two answers with no way
    // to tell which is in play.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    connect(&db, &env, scope, &org, "https://idp.example/entity").await;

    let id = SamlConnectionId::generate(&env, &scope);
    let second = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .saml_connections()
        .create(
            &env,
            NewSamlConnection {
                id: &id,
                organization_id: &org,
                display_name: "Okta again",
                idp_entity_id: "https://idp.example/entity",
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
        .await;
    assert!(
        matches!(second, Err(StoreError::Conflict)),
        "one organization pinned two connections to one identity provider: {second:?}"
    );
}

/// The SQLSTATE a CHECK constraint violation raises.
const CHECK_VIOLATION: &str = "23514";

/// Assert a write was refused BY A CHECK CONSTRAINT, not by anything else.
///
/// `is_err()` is not enough here. A scope refusal, a foreign key, a missing audit classification
/// and a constraint all answer `Err`, so a test asserting only that passes against a write that
/// never reached the column it names -- which is the shape that would let the constraint be
/// deleted with the suite still green.
fn assert_refused_by_a_constraint(outcome: &Result<(), StoreError>, what: &str) {
    let Err(StoreError::Database(error)) = outcome else {
        panic!("{what} was not refused by the database at all: {outcome:?}");
    };
    let code = error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned);
    assert_eq!(
        code.as_deref(),
        Some(CHECK_VIOLATION),
        "{what} was refused, but not by a CHECK constraint: {error:?}"
    );
}

#[tokio::test]
async fn a_key_the_verifier_could_not_be_handed_cannot_be_written() {
    // THE SHAPE IS ENFORCED WHERE IT IS STORED, not only where it is parsed. A row the verifier
    // cannot use would surface at somebody's sign-in as "the signature did not verify", which is
    // the same answer a forgery gets.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &org, "https://idp.example/entity").await;
    let now = now_micros(&env);
    let acting = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env));

    let attempt = async |kind: SamlKeyKind,
                         key: Vec<u8>,
                         exponent: Option<Vec<u8>>,
                         seed: u8,
                         not_before: i64,
                         not_after: i64| {
        let id = SamlCertificateId::generate(&env, &scope);
        acting
            .saml_connections()
            .pin_certificate(
                &env,
                NewSamlCertificate {
                    id: &id,
                    connection_id: &connection,
                    key_kind: kind,
                    public_key: &key,
                    rsa_exponent: exponent.as_deref(),
                    certificate_der: &[0x30, 0x82, seed],
                    fingerprint_sha256: &fingerprint(seed),
                    not_before_unix_micros: not_before,
                    not_after_unix_micros: not_after,
                },
                None,
                None,
            )
            .await
    };
    let (valid_from, valid_to) = (now - 1_000_000, now + 86_400_000_000);

    // RSA WITHOUT AN EXPONENT: `ring` needs both halves.
    assert_refused_by_a_constraint(
        &attempt(
            SamlKeyKind::Rsa,
            vec![0x01; 256],
            None,
            9,
            valid_from,
            valid_to,
        )
        .await,
        "an RSA key with no exponent",
    );
    // AN EC KEY *WITH* ONE, which is the mirror and which the CHECK also has to refuse: a row
    // carrying material for two different key types is one nobody can interpret.
    assert_refused_by_a_constraint(
        &attempt(
            SamlKeyKind::EcdsaP256,
            p256_point(12),
            Some(vec![0x01, 0x00, 0x01]),
            12,
            valid_from,
            valid_to,
        )
        .await,
        "an EC key carrying an RSA exponent",
    );
    // A P-256 POINT OF THE WRONG LENGTH.
    assert_refused_by_a_constraint(
        &attempt(
            SamlKeyKind::EcdsaP256,
            vec![0x04; 33],
            None,
            10,
            valid_from,
            valid_to,
        )
        .await,
        "a P-256 point of the wrong length",
    );
    // AN RSA MODULUS BELOW `ring`'S FLOOR. 1024 bits: the first version of this constraint
    // admitted it, and the key would have stored and then failed at every signature.
    assert_refused_by_a_constraint(
        &attempt(
            SamlKeyKind::Rsa,
            vec![0x01; 128],
            Some(vec![0x01, 0x00, 0x01]),
            13,
            valid_from,
            valid_to,
        )
        .await,
        "an RSA modulus below ring's 2048-bit floor",
    );
    // AND ABOVE ITS CEILING. 8192 bits is the largest `RSA_PKCS1_2048_8192_*` accepts, so one
    // byte past it is a key no signature can be checked against.
    assert_refused_by_a_constraint(
        &attempt(
            SamlKeyKind::Rsa,
            vec![0x01; 1025],
            Some(vec![0x01, 0x00, 0x01]),
            14,
            valid_from,
            valid_to,
        )
        .await,
        "an RSA modulus above ring's 8192-bit ceiling",
    );
    // A VALIDITY WINDOW NO CLOCK IS INSIDE.
    assert_refused_by_a_constraint(
        &attempt(
            SamlKeyKind::EcdsaP256,
            p256_point(11),
            None,
            11,
            valid_to,
            valid_from,
        )
        .await,
        "a certificate whose validity ends before it starts",
    );
}

#[tokio::test]
async fn every_rsa_size_ring_verifies_is_accepted() {
    // WHY THIS EXISTS. A bound that refuses valid input is worse than a loose one, because the
    // loose one fails visibly at the first signature while this one fails at CONFIGURATION, with
    // an identity provider an operator cannot connect at all and no explanation but a constraint
    // name.
    //
    // A version of this constraint named 256, 384 and 512 as "the three sizes ring will verify".
    // It is a range, 2048 to 8192 bits, and a customer on a 8192-bit key would have been locked
    // out. Only 2048 was ever written by a test, so narrowing it back would have gone unnoticed.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &org, "https://idp.example/entity").await;
    let now = now_micros(&env);
    let acting = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env));

    // The floor, a size in between that no enumeration would have listed, and the ceiling.
    for (n, bytes) in [256_usize, 640, 1024].into_iter().enumerate() {
        let seed = u8::try_from(n).expect("small") + 40;
        let id = SamlCertificateId::generate(&env, &scope);
        acting
            .saml_connections()
            .pin_certificate(
                &env,
                NewSamlCertificate {
                    id: &id,
                    connection_id: &connection,
                    key_kind: SamlKeyKind::Rsa,
                    public_key: &vec![seed; bytes],
                    rsa_exponent: Some(&[0x01, 0x00, 0x01]),
                    certificate_der: &[0x30, 0x82, seed],
                    fingerprint_sha256: &fingerprint(seed),
                    not_before_unix_micros: now - 1_000_000,
                    not_after_unix_micros: now + 86_400_000_000,
                },
                None,
                None,
            )
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "a {}-bit RSA key, which ring verifies, could not be pinned: {error:?}",
                    bytes * 8
                )
            });
    }
}

#[tokio::test]
async fn every_key_kind_round_trips_and_an_unknown_one_does_not() {
    // The vocabulary is a CHECK constraint and an enum, and this is what keeps them in step: a
    // kind added to one and not the other is a row this binary writes and cannot read back.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &org, "https://idp.example/entity").await;
    let now = now_micros(&env);
    let acting = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env));

    for (n, kind) in SamlKeyKind::ALL.into_iter().enumerate() {
        let seed = u8::try_from(n).expect("small") + 20;
        let (key, exponent) = match kind {
            SamlKeyKind::EcdsaP256 => (p256_point(seed), None),
            SamlKeyKind::EcdsaP384 => {
                let mut point = vec![0x04];
                point.extend(std::iter::repeat_n(seed, 96));
                (point, None)
            }
            SamlKeyKind::Rsa => (vec![seed; 256], Some(vec![0x01, 0x00, 0x01])),
        };
        let id = SamlCertificateId::generate(&env, &scope);
        acting
            .saml_connections()
            .pin_certificate(
                &env,
                NewSamlCertificate {
                    id: &id,
                    connection_id: &connection,
                    key_kind: kind,
                    public_key: &key,
                    rsa_exponent: exponent.as_deref(),
                    certificate_der: &[0x30, 0x82, seed],
                    fingerprint_sha256: &fingerprint(seed),
                    not_before_unix_micros: now - 1_000_000,
                    not_after_unix_micros: now + 86_400_000_000,
                },
                None,
                None,
            )
            .await
            .unwrap_or_else(|error| panic!("{} did not round trip: {error:?}", kind.as_str()));
    }

    let store = db.store().scoped(scope);
    let pinned = store
        .saml_connections()
        .certificates(&connection)
        .await
        .expect("read the pins");
    assert_eq!(pinned.len(), SamlKeyKind::ALL.len());
    for kind in SamlKeyKind::ALL {
        assert!(
            pinned.iter().any(|c| c.key_kind == kind),
            "{} did not read back",
            kind.as_str()
        );
    }
    // AND A VALUE OUTSIDE THE VOCABULARY IS REFUSED BY THE COLUMN, so a kind added to the enum
    // and not the CHECK is caught here rather than at somebody's sign-in.
    //
    // THE KEY MATERIAL HERE MUST BE OTHERWISE LEGAL, or the insert fails on the point-length
    // CHECK first and proves nothing about the vocabulary. It cannot be: every branch of that
    // CHECK is keyed on a kind, so an unknown kind fails BOTH. The vocabulary CHECK is therefore
    // asserted by name below rather than by the insert merely failing.
    let raw = sqlx::query(
        "INSERT INTO saml_connection_certificates \
         (id, tenant_id, environment_id, connection_id, key_kind, public_key, certificate_der, \
          fingerprint_sha256, not_before, not_after) \
         VALUES ($1, $2, $3, $4, 'ed25519', $5, $6, $7, now(), now() + interval '1 day')",
    )
    .bind(SamlCertificateId::generate(&env, &scope).to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(connection.to_string())
    .bind(p256_point(99))
    .bind(vec![0x30_u8, 0x82, 0x99])
    .bind(fingerprint(99))
    .execute(db.owner_pool())
    .await;
    let error = raw.expect_err("a key kind outside the vocabulary was stored");
    let constraint = error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::constraint)
        .unwrap_or_default()
        .to_owned();
    assert_eq!(
        constraint, "saml_connection_certificates_key_kind_check",
        "the insert was refused, but not by the vocabulary CHECK, so this proves nothing about \
         the vocabulary: {error:?}"
    );
}
