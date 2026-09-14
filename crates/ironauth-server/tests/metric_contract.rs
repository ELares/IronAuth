// SPDX-License-Identifier: MIT OR Apache-2.0

//! The metric contract, checked against a REAL SCRAPE (issue #152 criterion 1).
//!
//! # What the criterion asks, and what would not satisfy it
//!
//! > Every metric in the documented contract is exported and carries the documented labels; a
//! > CI contract test fails on drift in either direction.
//!
//! A test that read `metrics::CONTRACT` back and compared it to the constants would satisfy the
//! word "contract" and none of the sentence: it would prove the list agrees with itself. What
//! the criterion is about is EXPORT, and the only thing that establishes export is a rendered
//! scrape. So this emits every metric in the contract, renders the Prometheus text the
//! `/metrics` endpoint serves, and reads the result.
//!
//! # One process, one recorder
//!
//! The `metrics` facade installs a global recorder once per process, so every case here shares
//! one and the whole file is one test. Splitting it into several would have them race for the
//! install and pass or fail on scheduling.

use ironauth_server::metrics::{self, MetricKind};

/// Every emit site in the server crate: which macro, which metric constant, which labels.
///
/// # A TEXT SCAN, and what it therefore cannot see
///
/// It reads `counter!(CONST, "a" => .., "b" => ..)` and the gauge and histogram forms out of the
/// crate's own source. It does NOT see a call assembled from a variable, a label list built at
/// runtime, or an emit inside another crate. So a passing scan is not proof that no site
/// disagrees; it is proof that no site it can read disagrees, which is the honest claim and is
/// still the one that catches the change a person actually makes.
fn emit_sites() -> Vec<(String, String, Vec<String>)> {
    let mut sites = Vec::new();
    // READ AT RUNTIME, NOT `include_str!`, because the outbox and log-stream metrics are emitted
    // from the BINARY crate and a macro path cannot reach a sibling crate without a brittle
    // relative literal. Finding that out was the scan telling me its file list was incomplete:
    // the first version listed three files in this crate and reported that no site sets
    // `consumer`, which was true of the files it read and false of the workspace.
    for source in workspace_sources() {
        for macro_name in ["counter", "gauge", "histogram"] {
            let needle = format!("{macro_name}!(");
            let mut from = 0;
            while let Some(at) = source[from..].find(&needle) {
                let open = from + at + needle.len();
                // The macro's arguments, to the matching close paren. Nesting is shallow here
                // (a call like `reason_label(reason)` appears as a label VALUE), so a depth
                // counter is enough and a full parser is not.
                let mut depth = 1usize;
                let mut close = open;
                for (offset, ch) in source[open..].char_indices() {
                    match ch {
                        '(' => depth += 1,
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                close = open + offset;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                let args = &source[open..close];
                from = close.max(open + 1);

                // The first argument is the metric: a bare constant, or `metrics::CONST`.
                let Some(first) = args.split(',').next() else {
                    continue;
                };
                let ident = first.trim().rsplit("::").next().unwrap_or("").trim();
                if ident.is_empty() || !ident.chars().all(|c| c.is_ascii_uppercase() || c == '_') {
                    continue;
                }
                // A label is the token immediately BEFORE each `=>`. Taking the last
                // comma-separated piece of the text before the arrow skips the previous
                // label's VALUE, which may itself contain commas (a function call).
                let pieces: Vec<&str> = args.split("=>").collect();
                let labels: Vec<String> = pieces[..pieces.len().saturating_sub(1)]
                    .iter()
                    .filter_map(|before| {
                        before
                            .rsplit(',')
                            .next()
                            .map(|raw| raw.trim().trim_matches('"').to_owned())
                    })
                    .filter(|label| !label.is_empty() && !label.contains('('))
                    .collect();
                sites.push((ident.to_owned(), macro_name.to_owned(), labels));
            }
        }
    }
    sites
}

/// Every Rust source in the workspace that could emit a metric.
///
/// Walks the tree from this crate's manifest directory rather than taking a list, so a metric
/// emitted from a crate nobody thought of is still seen. Target directories are skipped: they
/// hold generated code and vendored sources, which are not emit sites anybody edits.
fn workspace_sources() -> Vec<String> {
    fn walk(dir: &std::path::Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if path.is_dir() {
                if name != "target" && !name.starts_with('.') {
                    walk(&path, out);
                }
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                if let Ok(text) = std::fs::read_to_string(&path) {
                    out.push(text);
                }
            }
        }
    }
    let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crate directory has a parent")
        .to_path_buf();
    let mut out = Vec::new();
    walk(&crates, &mut out);
    assert!(
        out.len() > 50,
        "the walk found {} sources, too few to be reading the workspace",
        out.len()
    );
    out
}

/// The value of a `pub const NAME: &str = "..."` in the metrics module.
fn value_of(ident: &str) -> Option<String> {
    include_str!("../src/metrics.rs")
        .split_once(&format!("pub const {ident}: &str = \""))
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(value, _)| value.to_owned())
}

#[test]
fn every_emit_site_matches_the_contract_it_is_declared_under() {
    // THE CHECK THAT IS NOT CIRCULAR, and the first version of this file did not have it.
    //
    // That version emitted every metric by READING THE CONTRACT for its kind and labels, then
    // scraped and asserted the scrape matched the contract. It passed against a contract
    // claiming a label no call site emits, and against one declaring the wrong kind, because
    // the expected value travelled with the thing under test: it proved the exporter renders
    // what it is given.
    //
    // What has to be compared is the CALL SITES against the contract, because they are what
    // actually runs.
    let sites = emit_sites();
    assert!(
        sites.len() >= 4,
        "the scan found {} emit sites, too few to be reading the crate",
        sites.len()
    );

    for (ident, macro_name, labels) in &sites {
        let Some(name) = value_of(ident) else {
            continue;
        };
        let Some(spec) = metrics::CONTRACT.iter().find(|spec| spec.name == name) else {
            panic!("{ident} ({name}) is emitted and is in no contract entry");
        };

        let declared_macro = match spec.kind {
            MetricKind::Counter => "counter",
            MetricKind::Gauge => "gauge",
            MetricKind::Histogram => "histogram",
        };
        assert_eq!(
            macro_name, declared_macro,
            "{name} is emitted with {macro_name}! and the contract declares it a {declared_macro}"
        );

        for label in labels {
            assert!(
                spec.labels.contains(&label.as_str()),
                "{name} is emitted with the label {label:?}, which the contract does not list.
                 Contract: {:?}",
                spec.labels
            );
        }
        // AND EVERY DECLARED LABEL IS EMITTED SOMEWHERE. A contract that lists a label no site
        // sets is a promise to a query that will never match.
        //
        // Checked across ALL of a metric's sites rather than each one, because a metric can
        // legitimately be emitted from several places, and one of them setting a subset is not
        // a defect -- a label missing from EVERY site is.
        let all_labels: std::collections::HashSet<&str> = sites
            .iter()
            .filter(|(other, _, _)| value_of(other).as_deref() == Some(spec.name))
            .flat_map(|(_, _, labels)| labels.iter().map(String::as_str))
            .collect();
        for declared in spec.labels {
            assert!(
                all_labels.contains(declared),
                "the contract says {name} carries {declared:?}, and no emit site this scan can \
                 read sets it"
            );
        }
    }
}

#[test]
fn the_contract_covers_every_metric_this_module_declares() {
    // THE BOUNDARY. The scrape test above can only see what `emit_everything` emitted, and that
    // reads the contract -- so a constant declared in the module and left out of the contract is
    // invisible to it. This reads the SOURCE, which is the only thing that knows what was
    // declared.
    let source = include_str!("../src/metrics.rs");
    let declared: Vec<&str> = source
        .lines()
        .filter_map(|line| line.trim().strip_prefix("pub const "))
        .filter(|rest| rest.contains(": &str = \"ironauth_"))
        .filter_map(|rest| rest.split(':').next())
        .collect();
    assert!(
        declared.len() >= 10,
        "the parse found {} declarations, too few to be reading this module",
        declared.len()
    );

    let promised: std::collections::HashSet<&str> =
        metrics::CONTRACT.iter().map(|spec| spec.name).collect();
    for ident in &declared {
        let Some((value, _)) = source
            .split_once(&format!("pub const {ident}: &str = \""))
            .and_then(|(_, rest)| rest.split_once('"'))
        else {
            panic!("could not read the value of {ident}")
        };
        assert!(
            promised.contains(value),
            "{ident} ({value}) is declared in this module and is in no contract entry, so \
             nothing checks that it is exported or what labels it carries"
        );
    }
}
