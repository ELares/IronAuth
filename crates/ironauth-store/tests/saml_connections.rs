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
async fn the_assertion_consumer_resolves_by_issuer_and_an_operator_switch_stops_it() {
    // WHY BY ISSUER. A response arrives at a per-environment endpoint carrying an `Issuer` and
    // nothing else this deployment chose; the organization comes OUT of the lookup. That is what
    // stops a response signed by one customer's identity provider being aimed at another
    // customer's connection: the aiming is not the caller's to do.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = connect(&db, &env, scope, &org, "https://idp.example/entity").await;
    let store = db.store().scoped(scope);

    let found = store
        .saml_connections()
        .active_by_issuer("https://idp.example/entity")
        .await
        .expect("read")
        .expect("the issuer resolves");
    assert_eq!(found.id, connection);
    assert_eq!(
        found.organization_id, org,
        "the organization must come out of the lookup, not into it"
    );

    // AN UNKNOWN ISSUER RESOLVES TO NOTHING, which is what makes an unpinned identity provider
    // unable to get as far as signature checking.
    assert!(
        store
            .saml_connections()
            .active_by_issuer("https://attacker.example/entity")
            .await
            .expect("read")
            .is_none()
    );

    // AND AN OPERATOR'S SWITCH STOPS IT RESOLVING AT ALL.
    //
    // The lookup filters on `active`, and the first version of this slice had no way to set that
    // column: a filter nothing can make false is a defence in the shape of a comment. Removing
    // the filter left every test green, which is how it was found.
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .saml_connections()
        .set_active(&env, &connection, false, None)
        .await
        .expect("switch the connection off");
    assert!(
        store
            .saml_connections()
            .active_by_issuer("https://idp.example/entity")
            .await
            .expect("read")
            .is_none(),
        "a switched-off identity provider still resolves, so turning it off means only that the \
         management surface says so"
    );
    // THE ROW IS STILL THERE, with its pins, which is the difference from a deletion: switching
    // back on must not require re-pinning every key.
    let still_there = store
        .saml_connections()
        .find_in_org(&org, &connection)
        .await
        .expect("read")
        .expect("the connection was not deleted");
    assert!(!still_there.active);
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
    // The ACS resolves a response by its `Issuer`. Two connections in one organization naming one
    // identity provider would make "which connection asserted this" ambiguous at exactly the
    // moment the answer decides which trust anchors apply.
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

#[tokio::test]
async fn a_key_the_verifier_could_not_be_handed_cannot_be_written() {
    // THE SHAPE IS ENFORCED WHERE IT IS STORED, not only where it is parsed. A row claiming RSA
    // with no exponent, or a P-256 point of the wrong length, is one the verifier cannot use --
    // and the failure would surface at somebody's sign-in rather than at pinning, as
    // "the signature did not verify", which is the same answer a forgery gets.
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

    // RSA WITHOUT AN EXPONENT.
    let id = SamlCertificateId::generate(&env, &scope);
    let no_exponent = acting
        .saml_connections()
        .pin_certificate(
            &env,
            NewSamlCertificate {
                id: &id,
                connection_id: &connection,
                key_kind: SamlKeyKind::Rsa,
                public_key: &vec![0x01; 256],
                rsa_exponent: None,
                certificate_der: &[0x30, 0x82, 0x01],
                fingerprint_sha256: &fingerprint(9),
                not_before_unix_micros: now - 1_000_000,
                not_after_unix_micros: now + 86_400_000_000,
            },
            None,
            None,
        )
        .await;
    assert!(
        no_exponent.is_err(),
        "an RSA key with no exponent was stored, so the verifier gets a key it cannot use"
    );

    // A P-256 POINT OF THE WRONG LENGTH.
    let id = SamlCertificateId::generate(&env, &scope);
    let short_point = acting
        .saml_connections()
        .pin_certificate(
            &env,
            NewSamlCertificate {
                id: &id,
                connection_id: &connection,
                key_kind: SamlKeyKind::EcdsaP256,
                public_key: &vec![0x04; 33],
                rsa_exponent: None,
                certificate_der: &[0x30, 0x82, 0x02],
                fingerprint_sha256: &fingerprint(10),
                not_before_unix_micros: now - 1_000_000,
                not_after_unix_micros: now + 86_400_000_000,
            },
            None,
            None,
        )
        .await;
    assert!(
        short_point.is_err(),
        "a P-256 point of the wrong length was stored"
    );

    // A VALIDITY WINDOW NO CLOCK IS INSIDE.
    let id = SamlCertificateId::generate(&env, &scope);
    let inverted = acting
        .saml_connections()
        .pin_certificate(
            &env,
            NewSamlCertificate {
                id: &id,
                connection_id: &connection,
                key_kind: SamlKeyKind::EcdsaP256,
                public_key: &p256_point(11),
                rsa_exponent: None,
                certificate_der: &[0x30, 0x82, 0x03],
                fingerprint_sha256: &fingerprint(11),
                not_before_unix_micros: now + 86_400_000_000,
                not_after_unix_micros: now - 1_000_000,
            },
            None,
            None,
        )
        .await;
    assert!(
        inverted.is_err(),
        "a certificate whose validity ends before it starts was pinned, which is pinning nothing"
    );
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
    assert!(raw.is_err(), "a key kind outside the vocabulary was stored");
}
