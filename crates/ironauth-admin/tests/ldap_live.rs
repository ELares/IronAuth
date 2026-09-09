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
//! CI SETS THEM, in the `ldap-live` job, against the committed fixture in `deploy/fixtures/ldap`.
//! They remain `#[ignore]`d so every other lane reports them as not-run rather than green, which
//! is the same reasoning: a tick that means "did not run" is worse than a missing test.
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

use ironauth_admin::ldap_client::{
    Directory, DirectoryConfig, DirectoryError, SearchScope, TlsMode,
};
use ironauth_admin::ldap_groups::{GroupSource as _, expand};
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
        max_entries: 250_000,
        connect_timeout: Duration::from_secs(10),
    }
}

/// PROGRESS IS OBSERVABLE WHILE THE READ RUNS, and "while" is the part that took three attempts.
///
/// A `tracing::info!` produced nothing (a test binary installs no subscriber). A captured
/// subscriber passed alone and failed in the suite (`tracing` caches callsite interest globally,
/// so a thread-local subscriber loses the race against sibling threads with none). This is the
/// third: an explicit observer, the shape `ScimPushObserver` uses.
///
/// AND IT PROVES INTERLEAVING, not merely the sequence. A `Vec` compared after the search returned
/// records WHAT was reported and never WHEN, so hoisting every call out of the loop and emitting
/// the same numbers afterwards -- the exact regression this exists to catch -- passed. The
/// discriminator is the CEILING: an over-ceiling read returns early from inside the loop, so a
/// reporter that emits during the read has already said something and one that batches until
/// afterwards never runs at all. No clock, no spawned task, nothing to race.
#[tokio::test]
#[ignore = "needs a directory server; see the module header"]
async fn a_long_search_reports_progress_while_it_runs() {
    use ironauth_admin::ldap_client::SearchProgress;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Recorder(Mutex<Vec<(String, usize, usize)>>);
    impl SearchProgress for Recorder {
        fn entries_read(&self, base: &str, read: usize, ceiling: usize) {
            self.0
                .lock()
                .expect("lock")
                .push((base.to_owned(), read, ceiling));
        }
    }

    // THE WHOLE READ, at a page size of two over five people: two full pages and a partial one.
    let recorder = Arc::new(Recorder::default());
    let directory = Directory::connect(&config(url("IRONAUTH_LDAP_URL"), TlsMode::Plaintext, 2))
        .await
        .expect("connect")
        .with_progress(recorder.clone());
    let found = directory
        .search_all(
            BASE,
            SearchScope::Subtree,
            "(objectClass=inetOrgPerson)",
            &["uid".to_owned()],
        )
        .await
        .expect("search");
    assert_eq!(found.len(), 5, "the fixture's five must still arrive");

    let seen = recorder.0.lock().expect("lock").clone();
    let counts: Vec<usize> = seen.iter().map(|(_, read, _)| *read).collect();
    assert_eq!(
        counts,
        vec![2, 4, 5],
        "a five-entry read at a page size of two must report after each full page AND once at \
         the end, so a directory smaller than one page still reports: {counts:?}"
    );
    assert!(
        seen.iter()
            .all(|(base, _, ceiling)| base == BASE && *ceiling > 0),
        "every report must name the base being read and the ceiling it is under, or a caller \
         watching two connectors cannot tell which is which: {seen:?}"
    );

    // THE INTERLEAVING. A read that hits its ceiling returns from INSIDE the loop, so a reporter
    // that fires during the read has already said "2" and one that batches until the loop ends
    // says nothing at all. This is the assertion the sequence above cannot make.
    let midread = Arc::new(Recorder::default());
    let mut capped = config(url("IRONAUTH_LDAP_URL"), TlsMode::Plaintext, 2);
    capped.max_entries = 2;
    let refused = Directory::connect(&capped)
        .await
        .expect("connect")
        .with_progress(midread.clone())
        .search_all(
            BASE,
            SearchScope::Subtree,
            "(objectClass=inetOrgPerson)",
            &["uid".to_owned()],
        )
        .await;
    assert!(refused.is_err(), "the capped read must refuse");
    let during: Vec<usize> = midread
        .0
        .lock()
        .expect("lock")
        .iter()
        .map(|(_, read, _)| *read)
        .collect();
    assert_eq!(
        during,
        vec![2],
        "a read abandoned mid-stream reported {during:?}; progress that only appears after the \
         loop finishes is a summary, and a summary of a read that never finished is nothing"
    );
}

/// AND THE CADENCE FOLLOWS THE PAGE SIZE. Driven at a different size from the test above, so a
/// hardcoded modulus that happened to match one of them cannot satisfy both.
#[tokio::test]
#[ignore = "needs a directory server; see the module header"]
async fn the_progress_cadence_follows_the_page_size() {
    use ironauth_admin::ldap_client::SearchProgress;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Recorder(Mutex<Vec<usize>>);
    impl SearchProgress for Recorder {
        fn entries_read(&self, _base: &str, read: usize, _ceiling: usize) {
            self.0.lock().expect("lock").push(read);
        }
    }

    for (page, expected) in [(1, vec![1, 2, 3, 4, 5]), (3, vec![3, 5]), (500, vec![5])] {
        let recorder = Arc::new(Recorder::default());
        let directory =
            Directory::connect(&config(url("IRONAUTH_LDAP_URL"), TlsMode::Plaintext, page))
                .await
                .expect("connect")
                .with_progress(recorder.clone());
        directory
            .search_all(
                BASE,
                SearchScope::Subtree,
                "(objectClass=inetOrgPerson)",
                &["uid".to_owned()],
            )
            .await
            .expect("search");
        let seen = recorder.0.lock().expect("lock").clone();
        assert_eq!(
            seen, expected,
            "at a page size of {page} the reports must be {expected:?}, got {seen:?}"
        );
    }
}

/// A CEILING, NOT A TRUNCATION. Paging bounds what is on the wire at once; it does not bound what
/// the process holds, because the diff compares the WHOLE directory against the whole previous
/// snapshot. So a directory larger than the connector can hold has to be REFUSED -- returning the
/// entries that fit would reach the diff as everybody who did not fit having departed, which is
/// the same failure the referral refusal exists for and is unrecoverable under a delete policy.
///
/// Driven against the real server at a ceiling of two, so the refusal is five real entries
/// meeting a bound rather than a fixture arranged to be small.
#[tokio::test]
#[ignore = "needs a directory server; see the module header"]
async fn a_directory_larger_than_the_ceiling_is_refused_rather_than_returned_short() {
    let mut cfg = config(url("IRONAUTH_LDAP_URL"), TlsMode::Plaintext, 2);
    cfg.max_entries = 2;
    let directory = Directory::connect(&cfg).await.expect("connect");

    let refused = directory
        .search_all(
            BASE,
            SearchScope::Subtree,
            "(objectClass=inetOrgPerson)",
            &["uid".to_owned()],
        )
        .await;

    let Err(error) = refused else {
        panic!("a directory over the ceiling was returned short instead of refused");
    };
    assert!(
        matches!(error, DirectoryError::TooManyEntries { ceiling: 2 }),
        "the refusal must name the ceiling it hit: {error:?}"
    );

    // THE BOUNDARY, not merely "somewhere below five". With five people and a ceiling of two, any
    // implementation refusing at four or fewer also passes the assertion above -- a mutant using
    // `max_entries * 2` survived it. A ceiling of FOUR against five entries pins the edge: it
    // must still refuse, and a bound that had drifted upward by even one would return all five.
    let mut edge = config(url("IRONAUTH_LDAP_URL"), TlsMode::Plaintext, 2);
    edge.max_entries = 4;
    let refused_at_four = Directory::connect(&edge)
        .await
        .expect("connect")
        .search_all(
            BASE,
            SearchScope::Subtree,
            "(objectClass=inetOrgPerson)",
            &["uid".to_owned()],
        )
        .await;
    assert!(
        matches!(
            refused_at_four,
            Err(DirectoryError::TooManyEntries { ceiling: 4 })
        ),
        "a five-person directory must be refused at a ceiling of four: {refused_at_four:?}"
    );

    // AND EXACTLY AT THE SIZE IT HOLDS, it reads. Five people under a ceiling of five is the
    // other side of the same edge, and it is what says the bound is `>` rather than `>=` in the
    // direction that matters: a connector sized for its directory must not refuse it.
    let mut exact = config(url("IRONAUTH_LDAP_URL"), TlsMode::Plaintext, 2);
    exact.max_entries = 5;
    let at_capacity = Directory::connect(&exact)
        .await
        .expect("connect")
        .search_all(
            BASE,
            SearchScope::Subtree,
            "(objectClass=inetOrgPerson)",
            &["uid".to_owned()],
        )
        .await
        .expect("a directory exactly at the ceiling must read");
    assert_eq!(at_capacity.len(), 5, "{at_capacity:?}");

    // AND UNDER THE CEILING IT STILL READS EVERYBODY, or the bound would be a wall: a refusal
    // that fired for every directory would satisfy the assertion above.
    let mut roomy = config(url("IRONAUTH_LDAP_URL"), TlsMode::Plaintext, 2);
    roomy.max_entries = 250_000;
    let directory = Directory::connect(&roomy).await.expect("connect");
    let everyone = directory
        .search_all(
            BASE,
            SearchScope::Subtree,
            "(objectClass=inetOrgPerson)",
            &["uid".to_owned()],
        )
        .await
        .expect("a directory under the ceiling reads");
    assert_eq!(
        everyone.len(),
        5,
        "the fixture's five people must still arrive: {everyone:?}"
    );
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
    let dir = Directory::connect(&config(url("IRONAUTH_LDAP_URL"), TlsMode::Plaintext, 500))
        .await
        .expect("connect");

    let asked = dir
        .search_all(
            BASE,
            SearchScope::Subtree,
            "(uid=grace)",
            &attributes_to_request(&mapping),
        )
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
        .search_all(BASE, SearchScope::Subtree, "(uid=grace)", &hand_listed)
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

    // THE PREMISE, ASSERTED. Everything below depends on the server refusing an UNPAGED read of
    // these five, and the earlier version of this test only said so in a comment: swapping the
    // bind to one without the limit let it pass with the RFC 2696 adapter deleted. So issue the
    // unpaged search here and require the refusal, and the fixture can no longer drift out from
    // under the test silently.
    let (conn, mut raw) = ldap3::LdapConnAsync::new(&cfg.url).await.expect("connect");
    ldap3::drive!(conn);
    raw.simple_bind(&cfg.bind_dn, &cfg.bind_password)
        .await
        .expect("bind")
        .success()
        .expect("bind succeeds");
    let unpaged = raw
        .search(
            BASE,
            ldap3::Scope::Subtree,
            "(objectClass=inetOrgPerson)",
            vec!["uid"],
        )
        .await
        .expect("search completes")
        .success();
    assert!(
        matches!(&unpaged, Err(ldap3::LdapError::LdapResult { result }) if result.rc == 4),
        "the fixture must refuse an unpaged read with sizeLimitExceeded, or this test cannot \
         tell a client that pages from one that does not: {unpaged:?}"
    );
    raw.unbind().await.expect("unbind the raw handle");

    let dir = Directory::connect(&cfg).await.expect("connect as svc");
    let people = dir
        .search_all(
            BASE,
            SearchScope::Subtree,
            "(objectClass=inetOrgPerson)",
            &["uid".to_owned()],
        )
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
    let dir = Directory::connect(&config(url("IRONAUTH_LDAP_URL"), TlsMode::Plaintext, 500))
        .await
        .expect("connect");

    let found = dir
        .search_all(
            BASE,
            SearchScope::Subtree,
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

/// A SUBTREE THE SERVER REFERS ELSEWHERE IS REFUSED, not silently short.
///
/// `EntriesOnly` collects continuation references and `LdapResult::success` inspects only the
/// result code, so before the refusal existed a search spanning a referral returned `Ok` with a
/// list missing everything behind it -- `result: 0 Success` with `numReferences: 1`. That short
/// list is exactly what must not reach a deprovisioning comparison.
///
/// The refusal shipped untested: deleting the whole block left 43 of 43 tests green, and the
/// variant is `pub`, so not even a dead-code warning fired.
///
/// `ou=Referrals` holds one real person and one `referral` object pointing at a host that does
/// not exist. Nothing chases it, so the test cannot hang.
#[tokio::test]
#[ignore = "needs a directory server; see the module header"]
async fn a_subtree_the_server_refers_elsewhere_is_refused_rather_than_returned_short() {
    let dir = Directory::connect(&config(url("IRONAUTH_LDAP_URL"), TlsMode::Plaintext, 500))
        .await
        .expect("connect");

    let outcome = dir
        .search_all(
            "ou=Referrals,dc=example,dc=test",
            SearchScope::Subtree,
            "(objectClass=*)",
            &["uid".to_owned()],
        )
        .await;

    match outcome {
        Err(DirectoryError::Referred { referrals }) => assert!(
            referrals.iter().any(|r| r.contains("other.example.test")),
            "the refusal must name where the server pointed: {referrals:?}"
        ),
        other => panic!("a referred subtree must be refused, not returned short: {other:?}"),
    }

    // THE CONTROL: a subtree with no referral in it still succeeds, so the refusal is about
    // referrals and not about this client failing every search.
    let people = dir
        .search_all(
            BASE,
            SearchScope::Subtree,
            "(uid=grace)",
            &["uid".to_owned()],
        )
        .await
        .expect("an unreferred subtree still searches");
    assert_eq!(people.len(), 1);

    dir.disconnect().await.expect("unbind");
}

/// THE GROUP WALK, AGAINST THE REAL SERVER, THROUGH THE LIVE CLIENT.
///
/// `impl GroupSource for Directory` shipped with no test of any kind. It is not a delegation: it
/// does a base read for the member list, then one read per member to classify it, across three
/// `objectClass` dialects. The fixture has what this needs -- `cn=all-staff` contains a person
/// and `cn=engineering`, and `cn=engineering` contains a person and `cn=all-staff` back, a real
/// cycle a real server accepted.
#[tokio::test]
#[ignore = "needs a directory server; see the module header"]
async fn the_live_client_walks_a_real_group_graph_and_terminates_on_its_cycle() {
    let dir = Directory::connect(&config(url("IRONAUTH_LDAP_URL"), TlsMode::Plaintext, 500))
        .await
        .expect("connect");

    // Direct members first, so a failure here is not confused with a failure in the walk.
    let members = dir
        .direct_members("cn=all-staff,ou=Groups,dc=example,dc=test")
        .await
        .expect("all-staff resolves");
    let engineering = members
        .iter()
        .find(|m| m.dn.starts_with("cn=engineering,"))
        .expect("all-staff contains engineering");
    assert!(
        engineering.is_group,
        "a groupOfNames member must be classified as a group, or the walk never descends"
    );
    let ada = members
        .iter()
        .find(|m| m.dn.starts_with("uid=ada"))
        .expect("all-staff contains ada");
    assert!(!ada.is_group, "a person must not be classified as a group");

    // Then the whole walk, over the real cycle.
    let out = expand(
        &dir,
        &["cn=all-staff,ou=Groups,dc=example,dc=test".to_owned()],
        10,
    )
    .await
    .expect("expands");

    assert!(out.complete, "truncated_at={:?}", out.truncated_at);
    assert!(
        out.revisited
            .contains("cn=all-staff,ou=Groups,dc=example,dc=test"),
        "the real back-edge must be reported: {:?}",
        out.revisited
    );
    assert!(
        out.members.iter().any(|m| m.starts_with("uid=grace")),
        "grace is behind the nested group and must be reached: {:?}",
        out.members
    );

    dir.disconnect().await.expect("unbind");
}

/// A GROUP DN THAT DOES NOT RESOLVE IS AN ERROR, not an empty group.
///
/// This is the bug the first version shipped. `direct_members` returned `Ok(vec![])` for a DN the
/// server did not know, so `expand` produced an empty member set and reported `complete: true` --
/// which means `ldap_diff` does NOT refuse, and every principal reads as departed. A typo in a
/// connector's group DN would have deprovisioned the directory.
#[tokio::test]
#[ignore = "needs a directory server; see the module header"]
async fn a_group_dn_that_does_not_resolve_is_refused_rather_than_read_as_empty() {
    let dir = Directory::connect(&config(url("IRONAUTH_LDAP_URL"), TlsMode::Plaintext, 500))
        .await
        .expect("connect");

    let missing = "cn=no-such-group,ou=Groups,dc=example,dc=test";
    let outcome = dir.direct_members(missing).await;
    assert!(
        matches!(&outcome, Err(DirectoryError::GroupNotFound { dn }) if dn == missing),
        "a missing group must be refused: {outcome:?}"
    );

    // AND THE WALK PROPAGATES IT, which is the half that matters: the alternative was an
    // expansion of nobody that called itself complete.
    let walked = expand(&dir, &[missing.to_owned()], 5).await;
    assert!(
        walked.is_err(),
        "an unresolvable root must abort the walk, not produce a complete empty one"
    );

    dir.disconnect().await.expect("unbind");
}
