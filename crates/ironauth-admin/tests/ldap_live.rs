// SPDX-License-Identifier: MIT OR Apache-2.0

//! The directory client against a REAL LDAP server (issue #142).
//!
//! Everything else in this series runs against a fixture. These four run against `slapd`, because
//! three of the properties the design rests on are properties of the PROTOCOL and a fixture that
//! asserts them is only asserting my belief about the protocol:
//!
//!   * `entryUUID` is operational, so a search that does not name it does not receive it;
//!   * a `StartTLS` upgrade a server cannot honour must fail rather than leave a plaintext socket;
//!   * paging returns everything across page boundaries.
//!
//! Set `IRONAUTH_LDAP_URL` (plus `_BIND_DN` and `_BIND_PASSWORD`) to run them. Unset, they SKIP
//! rather than pass silently: a green tick that means "did not run" is worse than a missing test,
//! so each one prints that it skipped.

use std::time::Duration;

use ironauth_admin::ldap_client::{Directory, DirectoryConfig, TlsMode};
use ironauth_admin::ldap_mapping::{StableIdSource, attributes_to_request, principal_for};
use serde_json::json;

const BASE: &str = "ou=People,dc=example,dc=test";

struct Server {
    url: String,
    bind_dn: String,
    bind_password: String,
}

/// The server to talk to, or `None` when this environment has none.
fn server() -> Option<Server> {
    let url = std::env::var("IRONAUTH_LDAP_URL").ok()?;
    Some(Server {
        url,
        bind_dn: std::env::var("IRONAUTH_LDAP_BIND_DN")
            .unwrap_or_else(|_| "cn=admin,dc=example,dc=test".to_owned()),
        bind_password: std::env::var("IRONAUTH_LDAP_BIND_PASSWORD")
            .unwrap_or_else(|_| "adminpw".to_owned()),
    })
}

fn config(server: &Server, tls_mode: TlsMode, page_size: i32) -> DirectoryConfig {
    DirectoryConfig {
        url: server.url.clone(),
        tls_mode,
        bind_dn: server.bind_dn.clone(),
        bind_password: server.bind_password.clone(),
        page_size,
        connect_timeout: Duration::from_secs(10),
    }
}

macro_rules! server_or_skip {
    ($name:literal) => {
        match server() {
            Some(s) => s,
            None => {
                eprintln!("SKIPPED {}: set IRONAUTH_LDAP_URL to run it", $name);
                return;
            }
        }
    };
}

/// The derived attribute list really does bring back the identifier.
///
/// `entryUUID` is an OPERATIONAL attribute: a search returns user attributes by default and
/// operational ones only when named. The second half of this test is the one that matters --
/// searching WITHOUT the derived list gets no identifier, so every entry would fall through to
/// the rename-fragile DN with nothing logged.
#[tokio::test]
async fn the_derived_attribute_list_is_what_makes_the_identifier_arrive() {
    let server = server_or_skip!("the_derived_attribute_list_is_what_makes_the_identifier_arrive");
    let mapping = json!({ "username": "uid", "email": "mail", "display_name": "cn" });

    let mut dir = Directory::connect(&config(&server, TlsMode::Plaintext, 500))
        .await
        .expect("connect");

    let asked = dir
        .search_all(BASE, "(uid=grace)", &attributes_to_request(&mapping), 500)
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

    // THE CONTROL. The same search naming only the mapped attributes gets no identifier at all,
    // and the mapper degrades to the DN without complaining. This is the defect the derivation
    // exists to prevent, reproduced against the real server.
    let hand_listed = vec!["uid".to_owned(), "mail".to_owned(), "cn".to_owned()];
    let without = dir
        .search_all(BASE, "(uid=grace)", &hand_listed, 500)
        .await
        .expect("search with a hand-listed set");
    let degraded = principal_for(without.first().expect("found"), &mapping).expect("maps");
    assert_eq!(
        degraded.stable_id_source,
        StableIdSource::DistinguishedName,
        "if this is not the DN then entryUUID came back unasked and the whole derivation is \
         unnecessary"
    );
    assert!(!degraded.stable_id_source.survives_rename());

    dir.disconnect().await.expect("unbind");
}

/// A `StartTLS` upgrade the server cannot honour must FAIL.
///
/// The fixture directory serves plaintext only. The dangerous outcome is not a refused
/// connection, it is a connection that succeeds in the clear while the connector says
/// `starttls` -- the bind sends the service account password. `ldap3` surfaces the refusal and
/// this asserts it is fatal.
#[tokio::test]
async fn starttls_against_a_server_without_tls_fails_rather_than_binding_in_the_clear() {
    let server = server_or_skip!("starttls_against_a_server_without_tls_fails...");

    // The control: the SAME URL and credentials bind fine in plaintext mode, so the failure below
    // is the transport rule and not a wrong address or a bad password.
    Directory::connect(&config(&server, TlsMode::Plaintext, 500))
        .await
        .expect("plaintext binds, so the address and credentials are good")
        .disconnect()
        .await
        .expect("unbind");

    let outcome = Directory::connect(&config(&server, TlsMode::StartTls, 500)).await;
    assert!(
        outcome.is_err(),
        "StartTLS succeeded against a server with no TLS: the bind would have crossed the \
         network in the clear while the connector said it was encrypted"
    );
}

/// Paging returns everything, across a boundary the server actually has to cross.
///
/// Page size 1 against a directory with several people means several round trips and a cookie
/// each time. A client that read only the first page would return one person, and the sync would
/// read the rest as departures.
#[tokio::test]
async fn a_page_size_of_one_still_returns_every_person() {
    let server = server_or_skip!("a_page_size_of_one_still_returns_every_person");
    let mut dir = Directory::connect(&config(&server, TlsMode::Plaintext, 1))
        .await
        .expect("connect");

    let one_at_a_time = dir
        .search_all(BASE, "(objectClass=inetOrgPerson)", &["uid".to_owned()], 1)
        .await
        .expect("paged search");
    let all_at_once = dir
        .search_all(
            BASE,
            "(objectClass=inetOrgPerson)",
            &["uid".to_owned()],
            500,
        )
        .await
        .expect("unpaged search");

    assert!(
        all_at_once.len() > 1,
        "the fixture directory needs more than one person for this to test paging at all"
    );
    assert_eq!(
        one_at_a_time.len(),
        all_at_once.len(),
        "a page size of 1 lost entries: {} vs {}",
        one_at_a_time.len(),
        all_at_once.len()
    );

    let mut paged: Vec<String> = one_at_a_time.iter().map(|e| e.dn.clone()).collect();
    let mut whole: Vec<String> = all_at_once.iter().map(|e| e.dn.clone()).collect();
    paged.sort();
    whole.sort();
    assert_eq!(paged, whole);

    dir.disconnect().await.expect("unbind");
}

/// A URL whose scheme disagrees with the mode never opens a socket.
///
/// The pure test asserts `validate` refuses it; this asserts `connect` consults `validate` before
/// reaching the network, by pointing `ldaps` at the plaintext port and requiring the refusal to
/// be the transport rule rather than a TLS handshake error.
#[tokio::test]
async fn connect_refuses_a_disagreeing_scheme_before_it_reaches_the_network() {
    let server = server_or_skip!("connect_refuses_a_disagreeing_scheme...");
    let outcome = Directory::connect(&config(&server, TlsMode::Ldaps, 500)).await;
    let error = outcome.err().expect("must refuse");
    let rendered = error.to_string();
    assert!(
        rendered.contains("cannot be used with"),
        "the refusal must be the transport rule, not a handshake failure: {rendered}"
    );
}
