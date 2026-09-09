// SPDX-License-Identifier: MIT OR Apache-2.0

//! Directory transport rules and the derived attribute list (issue #142).
//!
//! Everything here is pure: the transport decision is made before a socket is opened, which is
//! the point of making it a separate step. The live-server tests are in `ldap_live.rs`.

use std::time::Duration;

use ironauth_admin::ldap_client::{Directory, DirectoryConfig, DirectoryError, TlsMode};
use ironauth_admin::ldap_mapping::attributes_to_request;
use serde_json::json;

fn config(url: &str, tls_mode: TlsMode) -> DirectoryConfig {
    DirectoryConfig {
        url: url.to_owned(),
        tls_mode,
        bind_dn: "cn=svc,dc=example,dc=test".to_owned(),
        bind_password: "pw".to_owned(),
        page_size: 500,
        connect_timeout: Duration::from_secs(5),
    }
}

/// THE DOWNGRADE. A connector that says `ldaps` pointed at a plaintext URL must not connect.
///
/// This is the one that matters: the bind sends the service account password, so a connection
/// that succeeds in the clear while the console shows "LDAPS" hands over the directory. Refusing
/// at validation means the mode is a rule rather than a label.
#[test]
fn ldaps_against_a_plaintext_url_is_refused_before_connecting() {
    let err = config("ldap://dir.example.test:389", TlsMode::Ldaps)
        .validate()
        .expect_err("must refuse");
    assert!(matches!(
        err,
        DirectoryError::SchemeDisagreesWithTlsMode {
            mode: TlsMode::Ldaps,
            ..
        }
    ));
}

/// And the other direction, because a mismatch means one of the two settings is a mistake even
/// when the result would still be encrypted.
#[test]
fn starttls_against_an_ldaps_url_is_refused() {
    let err = config("ldaps://dir.example.test:636", TlsMode::StartTls)
        .validate()
        .expect_err("must refuse");
    assert!(matches!(
        err,
        DirectoryError::SchemeDisagreesWithTlsMode { .. }
    ));
}

/// The three agreeing combinations are accepted, so the rule above is a real discrimination
/// rather than a validator that refuses everything.
#[test]
fn a_mode_that_matches_its_scheme_is_accepted() {
    config("ldaps://dir.example.test:636", TlsMode::Ldaps)
        .validate()
        .expect("ldaps on ldaps");
    config("ldap://dir.example.test:389", TlsMode::StartTls)
        .validate()
        .expect("starttls on ldap");
    config("ldap://dir.example.test:389", TlsMode::Plaintext)
        .validate()
        .expect("plaintext on ldap");
}

/// Scheme comparison folds case: URLs are not case-sensitive in their scheme, and an operator
/// pasting `LDAPS://` must not be told it disagrees with `ldaps`.
#[test]
fn the_scheme_check_folds_case() {
    config("LDAPS://dir.example.test:636", TlsMode::Ldaps)
        .validate()
        .expect("uppercase scheme is the same scheme");
}

/// Anything that is not an LDAP URL is refused rather than handed to the connector.
#[test]
fn a_non_ldap_url_is_refused() {
    let err = config("https://dir.example.test", TlsMode::Ldaps)
        .validate()
        .expect_err("must refuse");
    assert!(matches!(err, DirectoryError::UnsupportedScheme { .. }));
    // Not merely a prefix check: a scheme CONTAINING "ldap" is still not an ldap scheme.
    let err = config("xldap://dir.example.test", TlsMode::Plaintext)
        .validate()
        .expect_err("must refuse");
    assert!(matches!(err, DirectoryError::UnsupportedScheme { .. }));
}

/// THE OPERATIONAL-ATTRIBUTE RULE. Both identifiers are requested even when the operator mapped
/// nothing at all.
///
/// Verified against a live server: a search that does not name `entryUUID` does not receive it.
/// If this list omitted them, every entry would look like it had no UUID, every entry would take
/// the rename-fragile DN fallback, and nothing anywhere would say so.
#[test]
fn the_identifier_attributes_are_always_requested() {
    let derived = attributes_to_request(&json!({}));
    assert!(derived.contains(&"entryuuid".to_owned()), "{derived:?}");
    assert!(derived.contains(&"objectguid".to_owned()), "{derived:?}");
    // And the default username source, or a connector that configured nothing gets no login id.
    assert!(derived.contains(&"uid".to_owned()), "{derived:?}");
}

/// A mapped attribute is requested, lowercased to match how entries are keyed.
#[test]
fn mapped_attributes_are_requested_and_folded() {
    let derived = attributes_to_request(&json!({
        "username": "sAMAccountName",
        "email": "Mail",
    }));
    assert!(
        derived.contains(&"samaccountname".to_owned()),
        "{derived:?}"
    );
    assert!(derived.contains(&"mail".to_owned()), "{derived:?}");
    // Still both identifiers, because a mapping never removes them.
    assert!(derived.contains(&"entryuuid".to_owned()));
    assert!(derived.contains(&"objectguid".to_owned()));
}

/// The list is deduplicated: mapping something onto `uid` must not request it twice.
#[test]
fn the_requested_list_has_no_duplicates() {
    let derived = attributes_to_request(&json!({ "username": "uid", "display_name": "UID" }));
    let uids = derived.iter().filter(|a| a.as_str() == "uid").count();
    assert_eq!(uids, 1, "{derived:?}");
}

/// A malformed mapping does not produce a search that omits the identifiers: the attribute list
/// degrades to the safe default rather than to nothing.
#[test]
fn a_malformed_mapping_still_requests_the_identifiers() {
    for bad in [json!("not an object"), json!([1, 2]), json!(null)] {
        let derived = attributes_to_request(&bad);
        assert!(
            derived.contains(&"entryuuid".to_owned()),
            "{bad} -> {derived:?}"
        );
        assert!(
            derived.contains(&"objectguid".to_owned()),
            "{bad} -> {derived:?}"
        );
    }
}

/// `connect` consults `validate` BEFORE it reaches the network.
///
/// THIS NEEDS NO SERVER, which is why it lives here rather than in the ignored live suite. It
/// was `#[ignore]`d there with the reason "needs a directory server", which was false -- it
/// points at a port nothing listens on -- and that false reason kept the PR's headline transport
/// property out of CI entirely.
///
/// Pointed at a port nothing listens on. If the transport rule were checked after the socket
/// attempt, the error would be a connection failure; the scheme error can only come from a check
/// that ran first. An earlier version pointed at the live server, where moving `validate` to
/// after the bind left the test green because the error text was identical either way.
#[tokio::test]
async fn connect_refuses_a_disagreeing_scheme_before_it_reaches_the_network() {
    // Port 1 on the loopback: reserved, and nothing listens there.
    let error = Directory::connect(&config("ldap://127.0.0.1:1", TlsMode::Ldaps))
        .await
        .err()
        .expect("must refuse");

    let rendered = error.to_string();
    assert!(
        rendered.contains("cannot be used with"),
        "the refusal must be the transport rule, not a connection failure: {rendered}"
    );

    // And the CONTROL that makes the above mean something: the same dead address WITH an
    // agreeing scheme gets past validation and fails on the network instead.
    let network = Directory::connect(&config("ldap://127.0.0.1:1", TlsMode::Plaintext))
        .await
        .err()
        .expect("nothing listens there");
    assert!(
        !network.to_string().contains("cannot be used with"),
        "an agreeing scheme must reach the network: {network}"
    );
}
