// SPDX-License-Identifier: MIT OR Apache-2.0

//! The VERSIONED export fixture a consumer pins against (issue #145 criterion 1).
//!
//! # Why a committed file and not another round trip
//!
//! `access_review.rs` already writes both formats and reads them back with an independent
//! parser, which proves the two halves agree. It cannot prove the format did not CHANGE:
//! rename a column, reorder the header, stop quoting, switch the line ending, and the round
//! trip still passes because both halves moved together. A `SailPoint`- or `Vanta`-class consumer
//! pins the bytes, and the thing that breaks it is exactly the change a round trip cannot see.
//!
//! So `tests/fixtures/access-review-v1.{jsonl,csv}` are the wire format of version 1, frozen.
//! They are generated FROM the writer rather than hand-authored, because a hand-authored file
//! would pin what the author believed the format to be; what a consumer receives is what the
//! writer emits. Freezing them is what makes them a contract.
//!
//! # Changing them
//!
//! A change to these files is a change to a published contract. ADDING a column is compatible
//! and the file is regenerated (a consumer reading by name is unaffected, one reading by
//! position keeps every column it had, which is why columns are appended and never inserted).
//! RENAMING, REORDERING or REMOVING one is not: that needs `access-review-v2` beside this file
//! and both served, because the whole point of a pinned fixture is that a consumer's ingest
//! does not break on a Tuesday.

use ironauth_store::access_review::{
    parse_csv, parse_jsonl, to_csv, to_jsonl, AccessReviewRow, ACCESS_REVIEW_COLUMNS,
};
use std::path::Path;

/// The rows the fixture files hold, in file order.
///
/// SYNTHETIC IDS, deliberately. Real ids embed a scope and are minted per run, so a fixture
/// built from a live export could never be compared byte for byte against anything.
///
/// Every `source` the export can emit appears at least once, including the `none` row for a
/// member who holds nothing -- the row an access review exists to surface and the one most
/// likely to be dropped by a writer that iterates grants. The last row's slug carries a comma
/// AND a quote, so the fixture pins the QUOTING and not only the columns: a writer that
/// stopped quoting would produce a different file and this test would say so.
fn fixture_rows() -> Vec<AccessReviewRow> {
    vec![
        row("user", "omb_alice", "usr_alice", "billing-admin", "direct", None, None, None),
        row("user", "omb_alice", "usr_alice", "member", "default", None, None, None),
        row(
            "user",
            "omb_bob",
            "usr_bob",
            "reports-reader",
            "group",
            Some("grp_finance"),
            None,
            None,
        ),
        row("user", "omb_bob", "usr_bob", "member", "default", None, None, None),
        row(
            "user",
            "omb_carol",
            "usr_carol",
            "billing-admin",
            "time_boxed",
            None,
            Some("agr_quarterclose"),
            Some(1_767_225_600_000),
        ),
        row(
            "service_account",
            "omb_robot",
            "sva_nightly",
            "reports-reader",
            "direct",
            None,
            None,
            None,
        ),
        row("user", "omb_dave", "usr_dave", "", "none", None, None, None),
        row(
            "user",
            "omb_eve",
            "usr_eve",
            "ops,\"emergency\"",
            "direct",
            None,
            None,
            None,
        ),
    ]
}

#[allow(clippy::too_many_arguments)]
fn row(
    principal_kind: &'static str,
    membership_id: &str,
    subject_id: &str,
    role_slug: &str,
    source: &'static str,
    via_group_id: Option<&str>,
    via_request_id: Option<&str>,
    granted_until_unix_ms: Option<i64>,
) -> AccessReviewRow {
    AccessReviewRow {
        organization_id: "org_fixture01".to_owned(),
        principal_kind,
        membership_id: membership_id.to_owned(),
        subject_id: subject_id.to_owned(),
        role_slug: role_slug.to_owned(),
        source,
        via_group_id: via_group_id.map(str::to_owned),
        via_request_id: via_request_id.map(str::to_owned),
        granted_until_unix_ms,
    }
}

fn fixture(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read the pinned fixture {}: {error}", path.display()))
}

/// Compare `produced` against the pinned file, or REWRITE it under
/// `IRONAUTH_REGENERATE_FIXTURES=1`.
///
/// The regeneration path exists because the fixture has to come from the WRITER and not from
/// an author's idea of the format. The first hand-authored version of this file ordered the
/// JSONL keys the way the CSV columns are ordered; the writer emits them alphabetically, and
/// the fixture was wrong in a way no reviewer would have caught by reading it.
///
/// It is NOT a way to make a failure go away. Regenerating is correct for an APPENDED column
/// and for nothing else: a rename, a reorder or a removal is a v2, and running this with the
/// variable set would quietly retire a contract instead of versioning it. The variable is
/// spelled out rather than defaulted for that reason.
fn pinned(name: &str, produced: &str, what: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    if std::env::var("IRONAUTH_REGENERATE_FIXTURES").as_deref() == Ok("1") {
        std::fs::write(&path, produced)
            .unwrap_or_else(|error| panic!("rewrite {}: {error}", path.display()));
        return;
    }
    assert_eq!(
        produced,
        fixture(name),
        "the {what} export drifted from the pinned version 1 fixture. If a column was \
         APPENDED this is compatible: rerun with IRONAUTH_REGENERATE_FIXTURES=1 and commit \
         the result. If one was renamed, reordered or removed, that is a v2 beside this file \
         and both have to be served"
    );
}

/// The writer still emits the bytes version 1 promised.
///
/// BYTE FOR BYTE, which is the only comparison that catches the changes a consumer notices:
/// a reordered header, a renamed column, a bare LF where the grammar says CRLF, a field that
/// stopped being quoted. Comparing parsed structures instead would pass through every one of
/// those.
#[test]
fn the_pinned_csv_is_what_the_writer_emits() {
    pinned("access-review-v1.csv", &to_csv(&fixture_rows()), "CSV");
}

#[test]
fn the_pinned_jsonl_is_what_the_writer_emits() {
    pinned("access-review-v1.jsonl", &to_jsonl(&fixture_rows()), "JSONL");
}

/// A consumer that has only the FILE reconstructs who has which role.
///
/// Nothing here touches `AccessReviewRow`: the fixture is read off disk, parsed by name off
/// its own header, and the answer is assembled from strings, which is what an outside tool
/// actually does. Asserting on the reconstruction rather than on the row count is the
/// difference between "the file parsed" and "the file says what it is for".
#[test]
fn a_consumer_reconstructs_who_has_which_role_from_the_pinned_files() {
    for (name, parsed) in [
        (
            "csv",
            parse_csv(&fixture("access-review-v1.csv")).expect("the pinned CSV parses"),
        ),
        (
            "jsonl",
            parse_jsonl(&fixture("access-review-v1.jsonl")).expect("the pinned JSONL parses"),
        ),
    ] {
        let field = |row: &ironauth_store::access_review::ConsumedRow, key: &str| {
            row.fields
                .get(key)
                .unwrap_or_else(|| panic!("{name}: no column {key}"))
                .clone()
        };

        // WHO HAS WHICH ROLE, BY WHICH PATH: the question the export exists to answer.
        let mut held: Vec<String> = parsed
            .iter()
            .filter(|row| field(row, "source") != "none")
            .map(|row| {
                let via = match field(row, "source").as_str() {
                    "group" => format!(" via {}", field(row, "via_group_id")),
                    "time_boxed" => format!(
                        " via {} until {}",
                        field(row, "via_request_id"),
                        field(row, "granted_until_unix_ms")
                    ),
                    _ => String::new(),
                };
                format!(
                    "{} ({}) holds {} by {}{}",
                    field(row, "subject_id"),
                    field(row, "principal_kind"),
                    field(row, "role_slug"),
                    field(row, "source"),
                    via
                )
            })
            .collect();
        held.sort();
        assert_eq!(
            held,
            vec![
                "sva_nightly (service_account) holds reports-reader by direct".to_owned(),
                "usr_alice (user) holds billing-admin by direct".to_owned(),
                "usr_alice (user) holds member by default".to_owned(),
                "usr_bob (user) holds member by default".to_owned(),
                "usr_bob (user) holds reports-reader by group via grp_finance".to_owned(),
                "usr_carol (user) holds billing-admin by time_boxed via agr_quarterclose \
                 until 1767225600000"
                    .to_owned(),
                "usr_eve (user) holds ops,\"emergency\" by direct".to_owned(),
            ],
            "{name}: the reconstruction does not match what the fixture records"
        );

        // AND THE PERSON WHO HOLDS NOTHING SURVIVES THE TRIP. "This employee has no access"
        // is a finding, and a consumer that drops the row cannot report it.
        let nobody: Vec<String> = parsed
            .iter()
            .filter(|row| field(row, "source") == "none")
            .map(|row| field(row, "subject_id"))
            .collect();
        assert_eq!(
            nobody,
            vec!["usr_dave".to_owned()],
            "{name}: the member holding nothing is missing from the parsed export"
        );
    }
}

/// The two pinned files describe the SAME review.
///
/// The cross-format check the round-trip test makes over in-process rows, made here over the
/// bytes a consumer receives. A column present in one format and absent from the other is the
/// defect a shared column list exists to prevent, and this is where it would show.
#[test]
fn the_two_pinned_files_are_one_review() {
    let from_csv = parse_csv(&fixture("access-review-v1.csv")).expect("the pinned CSV parses");
    let from_jsonl =
        parse_jsonl(&fixture("access-review-v1.jsonl")).expect("the pinned JSONL parses");
    assert_eq!(
        from_csv, from_jsonl,
        "the two pinned files do not describe the same access review"
    );
    assert_eq!(
        from_csv.len(),
        fixture_rows().len(),
        "the pinned files lost or gained a row"
    );
    for row in &from_csv {
        let mut columns: Vec<&str> = row.fields.keys().map(String::as_str).collect();
        columns.sort_unstable();
        let mut expected: Vec<&str> = ACCESS_REVIEW_COLUMNS.to_vec();
        expected.sort_unstable();
        assert_eq!(
            columns, expected,
            "a pinned row does not carry the published column set"
        );
    }
}
