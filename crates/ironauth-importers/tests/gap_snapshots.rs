// SPDX-License-Identifier: MIT OR Apache-2.0

//! Gap-report snapshot tests (issue #57).
//!
//! Renders the full validation-only gap report for each source's committed fixture
//! and diffs it against a committed snapshot, so a mapping regression (a field that
//! silently starts or stops being carried across) surfaces as a snapshot diff in
//! review. Run `IRONAUTH_UPDATE_SNAPSHOTS=1 cargo test -p ironauth-importers --test
//! gap_snapshots` to regenerate the snapshots after an intentional mapping change.

use std::path::PathBuf;

use ironauth_importers::firebase::FirebaseHashParams;
use ironauth_importers::{auth0, firebase, keycloak, ldap, scim};

fn snapshot_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/snapshots")
        .join(format!("{name}.txt"))
}

/// Compare `rendered` to the committed snapshot `name`, or rewrite it when
/// `IRONAUTH_UPDATE_SNAPSHOTS` is set.
fn assert_snapshot(name: &str, rendered: &str) {
    let path = snapshot_path(name);
    if std::env::var_os("IRONAUTH_UPDATE_SNAPSHOTS").is_some() {
        std::fs::write(&path, rendered).expect("write snapshot");
        return;
    }
    let expected = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read snapshot {}: {e}", path.display()));
    assert_eq!(
        rendered, expected,
        "gap-report snapshot '{name}' drifted; rerun with IRONAUTH_UPDATE_SNAPSHOTS=1 if intended"
    );
}

#[test]
fn keycloak_gap_report_snapshot() {
    let mapping = keycloak::map_realm(include_str!("fixtures/keycloak_realm.json")).expect("map");
    assert_snapshot("keycloak", &mapping.gap_report().render());
}

#[test]
fn auth0_gap_report_snapshot() {
    let mapping = auth0::map_export(
        include_str!("fixtures/auth0_users.json"),
        Some(include_str!("fixtures/auth0_password_hashes.ndjson")),
    )
    .expect("map");
    assert_snapshot("auth0", &mapping.gap_report().render());
}

#[test]
fn firebase_gap_report_snapshot() {
    let params =
        FirebaseHashParams::from_hash_config(include_str!("fixtures/firebase_hash_config.json"))
            .expect("hash config");
    let mapping =
        firebase::map_export(include_str!("fixtures/firebase_export.json"), &params).expect("map");
    assert_snapshot("firebase", &mapping.gap_report().render());
}

#[test]
fn scim_gap_report_snapshot() {
    let mapping = scim::map_users(include_str!("fixtures/scim_users.json")).expect("map");
    assert_snapshot("scim", &mapping.gap_report().render());
}

#[test]
fn ldap_gap_report_snapshot() {
    let mapping = ldap::map_entries(include_str!("fixtures/ldap_entries.json")).expect("map");
    assert_snapshot("ldap", &mapping.gap_report().render());
}
