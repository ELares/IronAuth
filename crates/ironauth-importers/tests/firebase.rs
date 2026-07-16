// SPDX-License-Identifier: MIT OR Apache-2.0

//! Firebase `auth:export` importer, fixture-based (issue #57).
//!
//! `frank`'s password hash is the published Firebase modified-scrypt vector
//! (password `user1password`), and the committed `firebase_hash_config.json`
//! carries the matching project parameters. Re-encoding the hash with those
//! parameters and verifying the original password proves Firebase modified-scrypt
//! verification works with fixture project parameters (the DB-backed login and
//! rehash is in `tests/login.rs`).

use ironauth_import::ForeignHash;
use ironauth_importers::firebase::{self, FirebaseHashParams};
use ironauth_importers::gap::MapOutcome;

const EXPORT: &str = include_str!("fixtures/firebase_export.json");
const HASH_CONFIG: &str = include_str!("fixtures/firebase_hash_config.json");

fn record<'a>(
    mapping: &'a ironauth_importers::Mapping,
    local_id: &str,
) -> &'a ironauth_import::ImportRecord {
    let user = mapping
        .users
        .iter()
        .find(|u| u.source_key == local_id)
        .expect("user");
    match &user.outcome {
        MapOutcome::Mapped(r) => r,
        MapOutcome::Dropped(reason) => panic!("expected {local_id} mapped, dropped: {reason}"),
    }
}

#[test]
fn frank_verifies_with_the_project_scrypt_parameters() {
    let params = FirebaseHashParams::from_hash_config(HASH_CONFIG).expect("hash config");
    let mapping = firebase::map_export(EXPORT, &params).expect("map");
    let frank = record(&mapping, "uid-frank-0001");
    assert_eq!(frank.identifier, "frank@acme.test");
    // customAttributes -> traits.
    let traits = frank.traits.as_ref().expect("traits");
    assert_eq!(traits["role"], "admin");
    // The modified-scrypt hash verifies the original password.
    let hash = frank.password_hash.as_deref().expect("hash");
    let parsed = ForeignHash::parse(hash).expect("parse");
    assert_eq!(parsed.tag(), "firebase-scrypt");
    assert!(
        parsed.verify(b"user1password"),
        "Firebase modified scrypt verifies with the fixture project parameters"
    );
    assert!(!parsed.verify(b"user1passwordX"));
}

#[test]
fn a_phone_and_social_user_maps_the_phone_and_reports_the_social_provider() {
    let params = FirebaseHashParams::from_hash_config(HASH_CONFIG).expect("hash config");
    let mapping = firebase::map_export(EXPORT, &params).expect("map");
    let grace = record(&mapping, "uid-grace-0002");
    // The phone identifier is mapped.
    let claims = grace.claims.as_ref().expect("claims");
    assert_eq!(claims["phone_number"], "+15550002222");
    assert_eq!(claims["phone_number_verified"], true);
    // No password (no password provider), reported.
    assert!(grace.password_hash.is_none());
    let user = mapping
        .users
        .iter()
        .find(|u| u.source_key == "uid-grace-0002")
        .unwrap();
    assert!(user.gaps.iter().any(|g| g.field == "providerUserInfo"));
    assert!(user.gaps.iter().any(|g| g.field == "passwordHash"));
}

#[test]
fn validation_only_report_covers_every_user() {
    let params = FirebaseHashParams::from_hash_config(HASH_CONFIG).expect("hash config");
    let mapping = firebase::map_export(EXPORT, &params).expect("map");
    let report = mapping.gap_report();
    assert_eq!(report.total, 2);
    assert_eq!(report.mapped, 2);
    assert_eq!(report.dropped, 0);
}
