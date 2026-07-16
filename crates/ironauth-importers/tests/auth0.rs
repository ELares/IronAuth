// SPDX-License-Identifier: MIT OR Apache-2.0

//! Auth0 bulk-export importer, fixture-based (issue #57).
//!
//! `carol`'s bcrypt hash in the committed hash export is a REAL hash of the
//! password `auth0-pw-1`; joining and verifying it proves credential intactness at
//! the hash-scheme boundary (the DB-backed login and rehash is in `tests/login.rs`).

use ironauth_import::ForeignHash;
use ironauth_importers::auth0;
use ironauth_importers::gap::MapOutcome;

const USERS: &str = include_str!("fixtures/auth0_users.json");
const HASHES: &str = include_str!("fixtures/auth0_password_hashes.ndjson");

fn record<'a>(
    mapping: &'a ironauth_importers::Mapping,
    id: &str,
) -> &'a ironauth_import::ImportRecord {
    let user = mapping
        .users
        .iter()
        .find(|u| u.source_key == id)
        .expect("user");
    match &user.outcome {
        MapOutcome::Mapped(r) => r,
        MapOutcome::Dropped(reason) => panic!("expected {id} mapped, dropped: {reason}"),
    }
}

#[test]
fn carol_joins_and_verifies_her_bcrypt_hash() {
    let mapping = auth0::map_export(USERS, Some(HASHES)).expect("map");
    let carol = record(&mapping, "auth0|5f00000000000000000000c1");
    assert_eq!(carol.identifier, "carol@acme.test");
    let claims = carol.claims.as_ref().expect("claims");
    assert_eq!(claims["name"], "Carol Carter");
    // Metadata mapped to traits.
    let traits = carol.traits.as_ref().expect("traits");
    assert_eq!(traits["app_metadata"]["plan"], "enterprise");
    assert_eq!(traits["user_metadata"]["locale"], "en-US");
    // The joined bcrypt hash verifies the original password.
    let hash = carol.password_hash.as_deref().expect("hash joined");
    let parsed = ForeignHash::parse(hash).expect("parse");
    assert_eq!(parsed.tag(), "bcrypt");
    assert!(parsed.verify(b"auth0-pw-1"), "original password verifies");
    assert!(!parsed.verify(b"nope"));
}

#[test]
fn a_social_user_is_credential_less_with_gaps() {
    let mapping = auth0::map_export(USERS, Some(HASHES)).expect("map");
    let dave = record(&mapping, "google-oauth2|110000000000000000011");
    assert!(dave.password_hash.is_none(), "social user has no hash");
    let user = mapping
        .users
        .iter()
        .find(|u| u.source_key == "google-oauth2|110000000000000000011")
        .unwrap();
    assert!(user.gaps.iter().any(|g| g.field == "passwordHash"));
    assert!(user.gaps.iter().any(|g| g.field.starts_with("identities")));
}

#[test]
fn a_blocked_user_maps_to_the_blocked_state() {
    let mapping = auth0::map_export(USERS, Some(HASHES)).expect("map");
    let erin = record(&mapping, "auth0|5f00000000000000000000e2");
    assert_eq!(erin.state.as_deref(), Some("blocked"));
    assert!(
        erin.password_hash.is_some(),
        "blocked user still keeps a credential"
    );
}

#[test]
fn without_the_hash_export_everyone_is_credential_less_but_reported() {
    let mapping = auth0::map_export(USERS, None).expect("map");
    let carol = record(&mapping, "auth0|5f00000000000000000000c1");
    assert!(carol.password_hash.is_none());
    let user = mapping
        .users
        .iter()
        .find(|u| u.source_key == "auth0|5f00000000000000000000c1")
        .unwrap();
    assert!(
        user.gaps.iter().any(|g| g.field == "passwordHash"),
        "a missing hash is reported, never silently dropped"
    );
}
