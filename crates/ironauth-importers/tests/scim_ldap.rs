// SPDX-License-Identifier: MIT OR Apache-2.0

//! Generic SCIM/LDAP escape-hatch importer, fixture-based (issue #57).
//!
//! The LDAP fixture includes three password schemes: `judy`'s `{PBKDF2-SHA256}` is
//! a REAL hash of `ldap-pw-1` (re-encoded and verified here, credential-intact),
//! `karl`'s `{SSHA}` is a weak SHA1 scheme reported as a gap, and `leo`'s
//! `{PBKDF2}` is HMAC-SHA1 and also reported. This proves the generic path imports
//! an LDAP hash scheme while reporting the ones IronAuth declines.

use ironauth_import::ForeignHash;
use ironauth_importers::gap::MapOutcome;
use ironauth_importers::{ldap, scim};

const SCIM: &str = include_str!("fixtures/scim_users.json");
const LDAP: &str = include_str!("fixtures/ldap_entries.json");

fn record<'a>(
    mapping: &'a ironauth_importers::Mapping,
    key: &str,
) -> &'a ironauth_import::ImportRecord {
    let user = mapping
        .users
        .iter()
        .find(|u| u.source_key == key)
        .expect("user");
    match &user.outcome {
        MapOutcome::Mapped(r) => r,
        MapOutcome::Dropped(reason) => panic!("expected {key} mapped, dropped: {reason}"),
    }
}

#[test]
fn scim_list_response_maps_with_claims_and_gaps() {
    let mapping = scim::map_users(SCIM).expect("map");
    let heidi = record(&mapping, "sp-2c7f0001");
    assert_eq!(heidi.identifier, "heidi");
    assert_eq!(heidi.external_id.as_deref(), Some("HR-9001"));
    let claims = heidi.claims.as_ref().expect("claims");
    assert_eq!(claims["email"], "heidi@acme.test");
    assert_eq!(claims["name"], "Heidi Hall");
    assert_eq!(claims["phone_number"], "+15550004444");
    // A SCIM user has no password by design; groups and the enterprise extension
    // are reported per record.
    assert!(heidi.password_hash.is_none());
    let user = mapping
        .users
        .iter()
        .find(|u| u.source_key == "sp-2c7f0001")
        .unwrap();
    let fields: Vec<&str> = user.gaps.iter().map(|g| g.field.as_str()).collect();
    assert!(fields.contains(&"groups"));
    assert!(fields.iter().any(|f| f.contains("enterprise")));
    // ivan is inactive.
    let ivan = record(&mapping, "ivan");
    assert_eq!(ivan.state.as_deref(), Some("disabled"));
}

#[test]
fn ldap_pbkdf2_credential_is_intact_and_weak_schemes_are_reported() {
    let mapping = ldap::map_entries(LDAP).expect("map");

    // judy: {PBKDF2-SHA256} re-encodes and verifies the original password.
    let judy = record(&mapping, "uid=judy,ou=people,dc=acme,dc=test");
    assert_eq!(judy.identifier, "judy");
    assert_eq!(judy.claims.as_ref().unwrap()["email"], "judy@acme.test");
    let hash = judy.password_hash.as_deref().expect("hash");
    let parsed = ForeignHash::parse(hash).expect("parse");
    assert_eq!(parsed.tag(), "pbkdf2");
    assert!(
        parsed.verify(b"ldap-pw-1"),
        "the original LDAP password verifies"
    );
    assert!(!parsed.verify(b"wrong"));

    // karl: {SSHA} is a reported gap, credential-less.
    let karl = record(&mapping, "uid=karl,ou=people,dc=acme,dc=test");
    assert!(karl.password_hash.is_none());
    let karl_user = mapping
        .users
        .iter()
        .find(|u| u.source_key == "uid=karl,ou=people,dc=acme,dc=test")
        .unwrap();
    assert!(
        karl_user
            .gaps
            .iter()
            .any(|g| g.field == "userPassword" && g.reason.contains("weak"))
    );

    // leo: {PBKDF2} (HMAC-SHA1) is reported, credential-less.
    let leo = record(&mapping, "uid=leo,ou=svc,dc=acme,dc=test");
    assert!(leo.password_hash.is_none());
    let leo_user = mapping
        .users
        .iter()
        .find(|u| u.source_key == "uid=leo,ou=svc,dc=acme,dc=test")
        .unwrap();
    assert!(
        leo_user
            .gaps
            .iter()
            .any(|g| g.field == "userPassword" && g.reason.contains("HMAC-SHA1"))
    );
}

#[test]
fn objectclass_and_extra_attributes_are_never_silently_dropped() {
    let mapping = ldap::map_entries(LDAP).expect("map");
    let judy = mapping
        .users
        .iter()
        .find(|u| u.source_key == "uid=judy,ou=people,dc=acme,dc=test")
        .unwrap();
    assert!(judy.gaps.iter().any(|g| g.field == "objectClass"));
}
