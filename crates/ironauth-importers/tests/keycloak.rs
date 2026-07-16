// SPDX-License-Identifier: MIT OR Apache-2.0

//! Keycloak realm-export importer, fixture-based (issue #57).
//!
//! Uses the committed sanitized realm export. `alice`'s PBKDF2-SHA256 credential is
//! a REAL hash of the password `keycloak-pw-1`, so re-encoding it and verifying the
//! original password proves credential intactness at the hash-scheme boundary (the
//! DB-backed login and rehash is in `tests/login.rs`).

use ironauth_import::ForeignHash;
use ironauth_importers::gap::MapOutcome;
use ironauth_importers::keycloak;

const REALM: &str = include_str!("fixtures/keycloak_realm.json");

fn mapped<'a>(
    mapping: &'a ironauth_importers::Mapping,
    key: &str,
) -> &'a ironauth_import::ImportRecord {
    let user = mapping
        .users
        .iter()
        .find(|u| {
            u.source_key == key
                || matches!(&u.outcome, MapOutcome::Mapped(r) if r.identifier == key)
        })
        .expect("user present");
    match &user.outcome {
        MapOutcome::Mapped(record) => record,
        MapOutcome::Dropped(reason) => panic!("expected {key} mapped, dropped: {reason}"),
    }
}

#[test]
fn alice_maps_with_a_verifiable_pbkdf2_credential() {
    let mapping = keycloak::map_realm(REALM).expect("parse realm");
    let alice = mapped(&mapping, "alice");
    assert_eq!(alice.identifier, "alice");
    assert_eq!(
        alice.external_id.as_deref(),
        Some("9f1c0e14-1111-4a2b-8c33-000000000001")
    );
    // Claims carried across.
    let claims = alice.claims.as_ref().expect("claims");
    assert_eq!(claims["email"], "alice@acme.test");
    assert_eq!(claims["email_verified"], true);
    assert_eq!(claims["given_name"], "Alice");
    assert_eq!(claims["family_name"], "Anderson");
    // Attributes carried as traits.
    let traits = alice.traits.as_ref().expect("traits");
    assert_eq!(traits["department"][0], "engineering");
    // The credential re-encodes to a recognized scheme and the ORIGINAL password
    // verifies: credential intactness at the hash-scheme boundary.
    let hash = alice.password_hash.as_deref().expect("hash");
    let parsed = ForeignHash::parse(hash).expect("recognized scheme");
    assert_eq!(parsed.tag(), "pbkdf2");
    assert!(
        parsed.verify(b"keycloak-pw-1"),
        "the original password verifies"
    );
    assert!(!parsed.verify(b"wrong-password"));
}

#[test]
fn bob_is_disabled_and_orphan_is_dropped() {
    let mapping = keycloak::map_realm(REALM).expect("parse realm");
    let bob = mapped(&mapping, "bob");
    assert_eq!(bob.state.as_deref(), Some("disabled"));

    let orphan = mapping
        .users
        .iter()
        .find(|u| u.source_key == "9f1c0e14-1111-4a2b-8c33-000000000003")
        .expect("orphan present");
    assert!(orphan.is_dropped(), "a user with no username is dropped");
}

#[test]
fn unmappable_constructs_are_reported_per_record() {
    let mapping = keycloak::map_realm(REALM).expect("parse realm");
    let alice = mapping
        .users
        .iter()
        .find(|u| u.source_key == "9f1c0e14-1111-4a2b-8c33-000000000001")
        .expect("alice");
    let fields: Vec<&str> = alice.gaps.iter().map(|g| g.field.as_str()).collect();
    assert!(fields.contains(&"realmRoles"), "roles reported: {fields:?}");
    assert!(fields.contains(&"clientRoles"));
    assert!(fields.contains(&"groups"));
    assert!(fields.contains(&"requiredActions"));
    assert!(fields.contains(&"federatedIdentities"));
    // The second credential (an OTP factor) is reported, not silently dropped.
    assert!(
        alice
            .gaps
            .iter()
            .any(|g| g.field.starts_with("credentials["))
    );
}

#[test]
fn validation_only_produces_a_gap_report_without_records() {
    // The validation-only pass is a pure transform: it yields the full report and
    // NEVER produces a store side effect (this crate cannot reach the store).
    let mapping = keycloak::map_realm(REALM).expect("parse realm");
    let report = mapping.gap_report();
    assert_eq!(report.total, 3);
    assert_eq!(report.mapped, 2, "alice and bob");
    assert_eq!(report.dropped, 1, "orphan");
    assert!(!report.is_clean());
    assert!(report.render().contains("keycloak import gap report"));
}
