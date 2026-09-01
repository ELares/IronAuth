// SPDX-License-Identifier: MIT OR Apache-2.0

//! Replaying provisioning traffic through the SCIM parsers (issue #135, criteria 1 and 2).
//!
//! # What a green run here means, and what it does not
//!
//! `tests/fixtures/PROVENANCE.md` says it plainly and this header repeats it because a test
//! file is where somebody will look: these bodies are DERIVED FROM SPECIFICATIONS AND VENDOR
//! DOCUMENTATION, not captured from a live tenant. A green run means the parsers accept the
//! shapes the specs describe. It does NOT mean they accept what Okta and Entra actually send.
//!
//! That gap is the whole reason issue #135 asks for recorded traffic: a fixture the
//! implementer writes proves the parser agrees with the implementer. This suite is therefore
//! the HARNESS, ready for real captures, plus a spec-derived corpus that is worth having in
//! the meantime because it catches shape regressions.
//!
//! The harness is deliberately data-driven: a real capture is dropped in as a file, with no
//! test code to change.

use std::fs;
use std::path::Path;

use ironauth_scim::{Filter, parse_filter, parse_patch_path, parse_resource_path};
use serde_json::Value;

/// Every fixture in the directory, so a file added and never wired up is impossible.
fn fixtures() -> Vec<(String, Value)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut out = Vec::new();
    for entry in fs::read_dir(&dir).expect("the fixture directory exists") {
        let path = entry.expect("a directory entry").path();
        if path.extension().is_some_and(|ext| ext == "json") {
            let name = path
                .file_name()
                .expect("a file name")
                .to_string_lossy()
                .into_owned();
            let text = fs::read_to_string(&path).expect("readable fixture");
            let value: Value = serde_json::from_str(&text)
                .unwrap_or_else(|error| panic!("{name} is not valid JSON: {error}"));
            out.push((name, value));
        }
    }
    out.sort_by(|left, right| left.0.cmp(&right.0));
    out
}

/// Every fixture states where it came from.
///
/// The provenance IS the finding here. A fixture with no stated source is one somebody will
/// later mistake for a capture, and the difference between "the parser agrees with the spec"
/// and "the parser agrees with Okta" is the entire value of this suite.
#[test]
fn every_fixture_states_its_provenance() {
    let all = fixtures();
    assert!(!all.is_empty(), "the fixture directory is not empty");
    for (name, fixture) in all {
        let source = fixture
            .get("source")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(
            !source.trim().is_empty(),
            "{name} must state where it came from"
        );
    }
}

/// Every fixture's resource path parses, and to the collection it names.
#[test]
fn every_fixture_path_parses() {
    let mut seen_collection = 0_usize;
    let mut seen_resource = 0_usize;
    for (name, fixture) in fixtures() {
        let Some(path) = fixture.get("path").and_then(Value::as_str) else {
            continue;
        };
        let parsed = parse_resource_path(path)
            .unwrap_or_else(|error| panic!("{name}: {path:?} must parse: {error}"));
        // A create posts to the collection and everything else addresses a resource, which is
        // the difference the id carries. Asserting only "it parsed" would pass on a parser
        // that dropped the id entirely.
        let expects_id = fixture.get("method").and_then(Value::as_str) != Some("POST")
            && fixture.get("method").and_then(Value::as_str) != Some("GET");
        assert_eq!(
            parsed.id().is_some(),
            expects_id,
            "{name}: {path:?} addresses the wrong thing"
        );
        if expects_id {
            seen_resource += 1;
        } else {
            seen_collection += 1;
        }
    }
    // The guard the loop needs to mean anything. Every `continue` above is silent, so a
    // corpus that lost its `path` keys, or a `fixtures()` that returned nothing, would run
    // zero iterations and report success. Both SHAPES are required, not just a nonzero
    // count: a corpus of only collection paths would never exercise the id branch, which is
    // the half that distinguishes `/Users` from `/Users/usr_a`.
    assert!(
        seen_collection > 0,
        "at least one fixture addresses a collection"
    );
    assert!(
        seen_resource > 0,
        "at least one fixture addresses an individual resource"
    );
}

/// Every fixture's PATCH path parses, including both provisioning dialects.
#[test]
fn every_fixture_patch_path_parses() {
    let mut seen_selector = false;
    let mut seen_bare = false;
    for (name, fixture) in fixtures() {
        let Some(path) = fixture.get("patch_path").and_then(Value::as_str) else {
            continue;
        };
        let parsed = parse_patch_path(path)
            .unwrap_or_else(|error| panic!("{name}: {path:?} must parse: {error:?}"));
        if parsed.selector().is_some() {
            seen_selector = true;
        } else {
            seen_bare = true;
        }
    }
    // BOTH dialects are actually exercised. Without this the suite could pass having only
    // ever seen one of them, which is how a dialect stops being covered without anyone
    // editing a test.
    assert!(
        seen_selector,
        "the Okta dialect (a filtered path) is covered"
    );
    assert!(seen_bare, "the Entra dialect (a bare path) is covered");
}

/// Every fixture's filter parses.
#[test]
fn every_fixture_filter_parses() {
    let mut checked = 0;
    let mut seen_value_path = false;
    for (name, fixture) in fixtures() {
        let Some(filter) = fixture.get("filter").and_then(Value::as_str) else {
            continue;
        };
        let parsed = parse_filter(filter)
            .unwrap_or_else(|error| panic!("{name}: {filter:?} must parse: {error}"));
        if matches!(parsed, Filter::ValuePath { .. }) {
            seen_value_path = true;
        }
        checked += 1;
    }
    assert!(checked > 0, "at least one fixture exercises a filter");
    // The bracketed form specifically. It is the one a server can omit and still pass every
    // simple-filter test while refusing what Okta and Entra actually send, so the corpus has
    // to hold one and this has to notice if it goes away.
    assert!(
        seen_value_path,
        "the corpus exercises a valuePath filter (RFC 7644 section 3.4.2.2)"
    );
}

/// The corpus covers the operations criterion 1 enumerates.
///
/// Pinned by NAME rather than by counting files, so adding a fixture does not make this pass
/// while one of the operations the criterion names is quietly missing.
#[test]
fn the_corpus_covers_every_operation_the_criterion_names() {
    let names: Vec<String> = fixtures().into_iter().map(|(name, _)| name).collect();
    for required in [
        "okta_create_user.json",
        "okta_deactivate_user.json",
        "okta_group_membership.json",
        "entra_patch_dialect.json",
        "entra_enterprise_user.json",
        "okta_filter_lookup.json",
        "entra_value_path_filter.json",
    ] {
        assert!(
            names.iter().any(|name| name == required),
            "the corpus is missing {required}; it covers {names:?}"
        );
    }
}
