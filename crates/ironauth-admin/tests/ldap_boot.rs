// SPDX-License-Identifier: MIT OR Apache-2.0

//! Turning stored connector rows into a runnable sweep (issue #142).
//!
//! The pure half: what a row MEANS to the client and the pass. Opening a connection and reading a
//! bind secret need a database and a directory, and are covered where those exist.

use ironauth_admin::ldap_boot::{inputs_for, tls_mode_for, url_for};
use ironauth_admin::ldap_client::TlsMode;
use ironauth_env::Env;
use ironauth_store::{
    LdapAbsencePolicy, LdapConnector, LdapConnectorId, LdapTlsMode, OrganizationId, Scope,
};

fn connector(tls: LdapTlsMode, port: u16, group_base: &str, depth: i32) -> LdapConnector {
    let env = Env::system();
    let scope = Scope::new(
        ironauth_store::TenantId::generate(&env),
        ironauth_store::EnvironmentId::generate(&env),
    );
    LdapConnector {
        id: LdapConnectorId::generate(&env, &scope),
        organization_id: OrganizationId::generate(&env, &scope),
        display_name: "Contoso AD".to_owned(),
        host: "ad.contoso.test".to_owned(),
        port,
        tls_mode: tls,
        bind_dn: "cn=svc,dc=contoso,dc=test".to_owned(),
        bind_secret_name: "contoso-bind".to_owned(),
        user_base_dn: "ou=people,dc=contoso,dc=test".to_owned(),
        group_base_dn: group_base.to_owned(),
        user_filter: "(objectClass=user)".to_owned(),
        group_filter: "(objectClass=group)".to_owned(),
        attribute_mapping: serde_json::json!({ "username": "sAMAccountName" }),
        absence_policy: LdapAbsencePolicy::Deactivate,
        max_group_depth: depth,
        active: true,
    }
}

/// The scheme follows the transport mode, because the client refuses a mismatch.
#[test]
fn the_url_scheme_follows_the_transport_mode() {
    assert_eq!(
        url_for(&connector(LdapTlsMode::Ldaps, 636, "", 5)),
        "ldaps://ad.contoso.test:636"
    );
    // StartTLS and plaintext both BEGIN in the clear, so both take the plain scheme. Emitting
    // ldaps:// for StartTLS would be refused by DirectoryConfig::validate as a disagreement --
    // correctly, but the operator would see a configuration error for a connector they set up
    // exactly as intended.
    assert_eq!(
        url_for(&connector(LdapTlsMode::StartTls, 389, "", 5)),
        "ldap://ad.contoso.test:389"
    );
    assert_eq!(
        url_for(&connector(LdapTlsMode::Plaintext, 389, "", 5)),
        "ldap://ad.contoso.test:389"
    );
}

/// Every stored mode maps to the client's mode, and none collapses into another.
#[test]
fn every_transport_mode_maps_to_itself() {
    assert_eq!(
        tls_mode_for(&connector(LdapTlsMode::Ldaps, 636, "", 5)),
        TlsMode::Ldaps
    );
    assert_eq!(
        tls_mode_for(&connector(LdapTlsMode::StartTls, 389, "", 5)),
        TlsMode::StartTls
    );
    assert_eq!(
        tls_mode_for(&connector(LdapTlsMode::Plaintext, 389, "", 5)),
        TlsMode::Plaintext
    );
}

/// A CONNECTOR WITH NO GROUP BASE HAS NO GROUP ROOTS, not one empty root.
///
/// This is the boot-path half of a hazard the walk now refuses: an unresolvable root aborts the
/// expansion. A blank `group_base_dn` turned into `vec![""]` would make every pass for that
/// connector fail on a DN nothing resolves -- when what the operator meant is "no group scoping,
/// everyone under the user base counts".
///
/// A ROW CAN NOW HOLD THIS DELIBERATELY. Until migration 0213 the column demanded
/// `group_base_dn <> ''`, which a single space satisfies -- so the arm was reachable only by an
/// operator who meant the opposite of what the row recorded. `ldap_connectors.rs` covers the
/// storage half, whitespace included.
#[test]
fn a_blank_group_base_means_no_group_scoping_rather_than_one_empty_root() {
    let inputs = inputs_for(&connector(LdapTlsMode::Ldaps, 636, "", 5));
    assert!(
        inputs.group_roots.is_empty(),
        "a blank group base must not become a root: {:?}",
        inputs.group_roots
    );
    // Whitespace is the same case: an operator who typed a space has not configured a group.
    let spaced = inputs_for(&connector(LdapTlsMode::Ldaps, 636, "   ", 5));
    assert!(spaced.group_roots.is_empty());

    // And a real base IS a root.
    let scoped = inputs_for(&connector(
        LdapTlsMode::Ldaps,
        636,
        "ou=groups,dc=contoso,dc=test",
        5,
    ));
    assert_eq!(scoped.group_roots, ["ou=groups,dc=contoso,dc=test"]);
}

/// The row's other fields reach the pass unchanged.
#[test]
fn the_pass_reads_the_row_it_was_given() {
    let row = connector(LdapTlsMode::Ldaps, 636, "ou=groups,dc=contoso,dc=test", 7);
    let inputs = inputs_for(&row);
    assert_eq!(inputs.user_base_dn, "ou=people,dc=contoso,dc=test");
    assert_eq!(inputs.user_filter, "(objectClass=user)");
    assert_eq!(inputs.max_group_depth, 7);
    assert_eq!(
        inputs.attribute_mapping,
        serde_json::json!({ "username": "sAMAccountName" }),
        "the mapping must arrive as stored; a dropped mapping falls back to defaults and \
         silently renames everybody"
    );
}

/// A depth a schema nobody wrote could hold is read as zero, not as a huge number.
///
/// The column carries a CHECK of 0..=64, so a negative value cannot be written today. `as u32` would
/// turn -1 into 4294967295 -- an unbounded walk over a customer's directory.
#[test]
fn a_negative_depth_reads_as_zero_rather_than_wrapping() {
    let inputs = inputs_for(&connector(LdapTlsMode::Ldaps, 636, "", -1));
    assert_eq!(inputs.max_group_depth, 0);
}
