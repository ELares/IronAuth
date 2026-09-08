// SPDX-License-Identifier: MIT OR Apache-2.0

//! The directory client against a REAL LDAP server (issue #142).
//!
//! Everything else in this series runs against a fixture. These run against `slapd`, because the
//! properties they cover are properties of the PROTOCOL, and a fixture asserting them only
//! asserts a belief about the protocol.
//!
//! # How these are run, stated exactly
//!
//! They are `#[ignore]`d. A default `cargo test` reports them as **ignored**, which is visibly
//! not-run. An earlier version instead returned early with an `eprintln!` and claimed to "skip
//! loudly"; that was false, because libtest captures the output of passing tests, so the run
//! printed nothing and reported four green ticks. A green tick meaning "did not run" is worse
//! than a missing test, and the harness already has a word for not-run.
//!
//! To run them:
//!
//! ```text
//! export IRONAUTH_LDAP_URL=ldap://<host>:<port>          # TLS-capable fixture
//! export IRONAUTH_LDAP_PLAINTEXT_URL=ldap://<host>:<port> # a server with NO TLS at all
//! cargo test -p ironauth-admin --all-features --test ldap_live -- --ignored
//! ```
//!
//! CI does not set these yet: the containerised directory fixture is a separate criterion of
//! #142 and is not claimed here.
//!
//! # What the fixture has to provide
//!
//! Two servers, because one of the properties is about a server that CANNOT do TLS:
//!
//!   * `IRONAUTH_LDAP_URL` -- a normal server. `ou=People` holds five `inetOrgPerson` entries.
//!     A bind DN `cn=svc` exists whose limits are `size.soft=2 size.prtotal=unlimited`, so an
//!     UNPAGED search of those five is refused with `sizeLimitExceeded` while a paged one
//!     succeeds. That asymmetry is what makes the paging test able to fail.
//!   * `IRONAUTH_LDAP_PLAINTEXT_URL` -- a server built with TLS switched off, which answers the
//!     `StartTLS` extended request with `protocolError`.

use std::time::Duration;

use ironauth_admin::ldap_client::{Directory, DirectoryConfig, TlsMode};
use ironauth_admin::ldap_mapping::{StableIdSource, attributes_to_request, principal_for};
use serde_json::json;

const BASE: &str = "ou=People,dc=example,dc=test";

fn url(var: &str) -> String {
    std::env::var(var)
        .unwrap_or_else(|_| panic!("{var} must be set to run this suite; see the module header"))
}

fn config(url: String, tls_mode: TlsMode, page_size: i32) -> DirectoryConfig {
    DirectoryConfig {
        url,
        tls_mode,
        bind_dn: std::env::var("IRONAUTH_LDAP_BIND_DN")
            .unwrap_or_else(|_| "cn=admin,dc=example,dc=test".to_owned()),
        bind_password: std::env::var("IRONAUTH_LDAP_BIND_PASSWORD")
            .unwrap_or_else(|_| "adminpw".to_owned()),
        page_size,
        connect_timeout: Duration::from_secs(10),
    }
}

/// The derived attribute list is what makes the identifier arrive.
///
/// `entryUUID` is an OPERATIONAL attribute: a search returns user attributes by default and
/// operational ones only when named. The CONTROL is the half that matters -- the same search
/// naming only the mapped attributes comes back with no identifier, and the mapper degrades to
/// the DN without complaining.
#[tokio::test]
#[ignore = "needs a directory server; see the module header"]
async fn the_derived_attribute_list_is_what_makes_the_identifier_arrive() {
    let mapping = json!({ "username": "uid", "email": "mail", "display_name": "cn" });
    let mut dir = Directory::connect(&config(url("IRONAUTH_LDAP_URL"), TlsMode::Plaintext, 500))
        .await
        .expect("connect");

    let asked = dir
        .search_all(BASE, "(uid=grace)", &attributes_to_request(&mapping))
        .await
        .expect("search with the derived list");
    let entry = asked.first().expect("grace is in the fixture directory");
    let mapped = principal_for(entry, &mapping).expect("maps");
    assert_eq!(mapped.username, "grace");
    assert_eq!(
        mapped.stable_id_source,
        StableIdSource::EntryUuid,
        "the derived list must bring back entryUUID; got {:?} for {}",
        mapped.stable_id_source,
        mapped.dn
    );

    let hand_listed = vec!["uid".to_owned(), "mail".to_owned(), "cn".to_owned()];
    let without = dir
        .search_all(BASE, "(uid=grace)", &hand_listed)
        .await
        .expect("search with a hand-listed set");
    let degraded = principal_for(without.first().expect("found"), &mapping).expect("maps");
    assert_eq!(
        degraded.stable_id_source,
        StableIdSource::DistinguishedName,
        "if this is not the DN then entryUUID came back unasked and the derivation is pointless"
    );
    assert!(!degraded.stable_id_source.survives_rename());

    dir.disconnect().await.expect("unbind");
}

/// A `StartTLS` upgrade the server DECLINES must fail, not fall back to plaintext.
///
/// This needs a server that genuinely cannot do TLS, which is why the fixture provides a second
/// one. An earlier version pointed at the TLS-capable server and called it "plaintext only": that
/// server accepts the upgrade (`resultCode 0`) and the connection failed later, inside the
/// handshake, on an expired certificate. The test passed for a reason unrelated to the property,
/// and `assert!(is_err())` would have accepted a DNS failure just as happily.
///
/// The bind sends the service account password, so a silent fallback hands over the directory.
#[tokio::test]
#[ignore = "needs a directory server; see the module header"]
async fn starttls_against_a_server_that_declines_the_upgrade_does_not_bind_in_the_clear() {
    let plaintext_only = url("IRONAUTH_LDAP_PLAINTEXT_URL");

    // CONTROL: the same URL and credentials bind fine when the connector asks for plaintext, so
    // the failure below is the transport rule rather than a bad address or a bad password.
    Directory::connect(&config(plaintext_only.clone(), TlsMode::Plaintext, 500))
        .await
        .expect("plaintext binds, so the address and credentials are good")
        .disconnect()
        .await
        .expect("unbind");

    let error = Directory::connect(&config(plaintext_only, TlsMode::StartTls, 500))
        .await
        .err()
        .expect("StartTLS against a server with no TLS must fail");

    // NOT merely `is_err()`. The server answers the extended request with `protocolError`, which
    // `ldap3` surfaces as a result-code failure. Naming it keeps the test from passing on a
    // handshake error, a reset, or a name-resolution failure -- any of which would leave the
    // actual property unmeasured.
    let rendered = error.to_string();
    assert!(
        rendered.contains("protocolError")
            || rendered.contains("protocol error")
            || rendered.contains("rc=2"),
        "the failure must be the DECLINED upgrade, not something incidental: {rendered}"
    );
}

/// Paging returns everything, and the test can tell whether paging happened.
///
/// The fixture's `cn=svc` carries `size.soft=2 size.prtotal=unlimited`, and `ou=People` holds
/// five people. So an UNPAGED search is refused with `sizeLimitExceeded` while a paged one walks
/// the whole set. An earlier version compared a page-size-1 search against a page-size-500 one
/// over two entries with no limit in force, and passed with the RFC 2696 adapter deleted
/// outright: both sides came from the same call and moved together.
#[tokio::test]
#[ignore = "needs a directory server; see the module header"]
async fn a_page_size_of_one_walks_past_a_limit_that_stops_an_unpaged_search() {
    let mut cfg = config(url("IRONAUTH_LDAP_URL"), TlsMode::Plaintext, 1);
    cfg.bind_dn = "cn=svc,dc=example,dc=test".to_owned();
    cfg.bind_password = "svcpw".to_owned();

    let mut dir = Directory::connect(&cfg).await.expect("connect as svc");
    let people = dir
        .search_all(BASE, "(objectClass=inetOrgPerson)", &["uid".to_owned()])
        .await
        .expect("a paged search must walk past the size limit");

    assert_eq!(
        people.len(),
        5,
        "expected the whole fixture; a client that stopped paging would be capped at the \
         server's soft limit of 2, and one that never paged would be refused outright"
    );

    dir.disconnect().await.expect("unbind");
}

/// `connect` consults `validate` BEFORE it reaches the network.
///
/// Pointed at a port nothing listens on. If the transport rule were checked after the socket
/// attempt, the error would be a connection failure; the scheme error can only come from a check
/// that ran first. An earlier version pointed at the live server, where moving `validate` to
/// after the bind left the test green because the error text was identical either way.
#[tokio::test]
#[ignore = "needs a directory server; see the module header"]
async fn connect_refuses_a_disagreeing_scheme_before_it_reaches_the_network() {
    // Port 1 on the loopback: reserved, and nothing listens there.
    let error = Directory::connect(&config(
        "ldap://127.0.0.1:1".to_owned(),
        TlsMode::Ldaps,
        500,
    ))
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
    let network = Directory::connect(&config(
        "ldap://127.0.0.1:1".to_owned(),
        TlsMode::Plaintext,
        500,
    ))
    .await
    .err()
    .expect("nothing listens there");
    assert!(
        !network.to_string().contains("cannot be used with"),
        "an agreeing scheme must reach the network: {network}"
    );
}

/// AN OCTET-STRING ATTRIBUTE SURVIVES THE SEARCH.
///
/// `ldap3` routes any value that is not valid UTF-8 into `bin_attrs` and never into `attrs`.
/// Active Directory's `objectGUID` is sixteen raw bytes, so a client that carried only the text
/// map would hand the mapper an entry with no identifier -- and every AD entry would take the
/// rename-fragile DN fallback, silently. The first version of `search_all` did exactly that: the
/// octet-string support in `ldap_mapping` had no producer at all.
///
/// `OpenLDAP` has no `objectGUID` in its schema, so the fixture carries a 16-byte non-UTF-8
/// `jpegPhoto` on `grace`, which exercises the same path: the server returns it, `ldap3` parses
/// it as binary, and this asserts the client did not drop it.
#[tokio::test]
#[ignore = "needs a directory server; see the module header"]
async fn an_octet_string_attribute_is_not_dropped_on_the_way_out() {
    let mut dir = Directory::connect(&config(url("IRONAUTH_LDAP_URL"), TlsMode::Plaintext, 500))
        .await
        .expect("connect");

    let found = dir
        .search_all(
            BASE,
            "(uid=grace)",
            &["uid".to_owned(), "jpegphoto".to_owned()],
        )
        .await
        .expect("search");
    let entry = found.first().expect("grace exists");

    // The text map must NOT hold it, or this fixture is not exercising the binary path at all.
    assert!(
        entry.values("jpegphoto").is_empty(),
        "a non-UTF-8 value must not arrive as text; this fixture is not testing what it claims"
    );
    assert_eq!(
        entry.binary_values("jpegphoto"),
        [vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff
        ]],
        "the octet-string value was dropped between ldap3 and DirectoryEntry"
    );

    dir.disconnect().await.expect("unbind");
}
